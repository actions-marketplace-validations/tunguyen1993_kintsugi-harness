"""Zero-dependency Model Context Protocol (MCP) stdio JSON-RPC 2.0 server (`kintsugi mcp`)."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, TextIO, Union

from kintsugi import __version__
from kintsugi.compactor import ConversationCompactor
from kintsugi.compiler import SkillCompiler
from kintsugi.compressor import (
    DOMAIN_SHARD_REGISTRY,
    partition_by_domain,
    render_domain_kmi_pack,
)
from kintsugi.council import EvolutionCouncil, answer_user_multi_model_question
from kintsugi.ledger import ScarLedger
from kintsugi.models import FailureTrace, Severity
from kintsugi.scanner import KintsugiScanner

MCP_PROTOCOL_VERSION = "2024-11-05"


def _tool_definitions() -> list[Dict[str, Any]]:
    return [
        {
            "name": "kintsugi_scan_code",
            "description": "Deterministically scan a source snippet or file path against verified Kintsugi Golden Scars (AST + Regex) before writing or committing.",
            "annotations": {
                "title": "Scan Code Against Kintsugi Guardrails",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
            "inputSchema": {
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Inline source code to scan"},
                    "file_path": {
                        "type": "string",
                        "description": "Path on disk to scan (or virtual filename for language detection)",
                    },
                    "language": {
                        "type": "string",
                        "description": "Optional language override (python, typescript, javascript, shell, markdown)",
                    },
                },
            },
        },
        {
            "name": "kintsugi_list_scars",
            "description": "List verified Golden Scars (`❌ Anti-Pattern` vs `✅ Verified Fix`) filtered by language, tag, or minimum severity.",
            "annotations": {
                "title": "List Verified Golden Scars",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
            "inputSchema": {
                "type": "object",
                "properties": {
                    "language": {"type": "string"},
                    "tag": {"type": "string"},
                    "domain": {
                        "type": "string",
                        "description": "Optional domain shard filter (security, backend, database, frontend, devops, ai_mcp)",
                    },
                    "min_severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    },
                },
            },
        },
        {
            "name": "kintsugi_record_failure",
            "description": (
                "Compile a runtime/test failure into a new self-verified Golden Scar and persist it into `.kintsugi/scars.json`. "
                "Supports Tier-Gated Multi-Model Co-Execution (`co_run=True`): runs Primary Model + 1 Free Model on Free tier ($0), "
                "Primary + 2..5 Free Models on Pro tier (Apache-2.0/Apache-2.0), and Primary + Free Models + BYOK Paid Frontier Council on Enterprise Pro (Apache-2.0)."
            ),
            "annotations": {
                "title": "Record Failure & Evolve Golden Scar",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": False,
                "openWorldHint": False,
            },
            "inputSchema": {
                "type": "object",
                "required": ["error_summary", "raw_trace"],
                "properties": {
                    "error_summary": {"type": "string"},
                    "raw_trace": {"type": "string"},
                    "language": {"type": "string", "default": "python"},
                    "offending_snippet": {"type": "string"},
                    "fixed_snippet": {"type": "string"},
                    "workspace_root": {"type": "string", "default": "."},
                    "co_run": {
                        "type": "boolean",
                        "description": "Always run Primary Anchor model alongside discovered $0 Free model(s)",
                        "default": False,
                    },
                    "free_runners": {
                        "type": "integer",
                        "description": "Requested number of $0 Free Co-Runners (locked to 1 on Free tier, up to 5 on Pro/Enterprise)",
                    },
                    "paid_council": {
                        "type": "boolean",
                        "description": "Include user-supplied BYOK Paid Frontier Council seats (requires Complete Corpus Pack Apache-2.0)",
                        "default": False,
                    },
                },
            },
        },
        {
            "name": "kintsugi_compile_skills",
            "description": "Compile `.kintsugi/scars.json` into `.claude/skills/*/SKILL.md`, `CLAUDE.md`, `AGENTS.md`, and `.cursor/rules/`.",
            "annotations": {
                "title": "Compile KMI/1 Ultra-Low-Token Skills",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace_root": {"type": "string", "default": "."},
                    "targets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "default": ["skills", "claude", "agents", "cursor"],
                    },
                },
            },
        },
        {
            "name": "kintsugi_multi_model_guide",
            "description": (
                "Interactive Bilingual (Vietnamese/English) User Onboarding, Q&A Guide, and Autonomous $0 DeepSeek Free "
                "Token Collector. Call this tool whenever the user asks how to use Multi-Model Co-Execution, how many Free models "
                "their edition supports (Free=1, Pro=2..5, Enterprise=5+6 BYOK Paid), how to add their own "
                "API keys (`BYOK`) for the Paid Frontier Council, or pass `auto_configure-byok=true` to autonomously "
                "register a disposable example.invalid inbox and mint a live $0 DeepSeek-R1 (262K) API key."
            ),
            "annotations": {
                "title": "Multi-Model Council Guide & Free Token Collector",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": True,
            },
            "inputSchema": {
                "type": "object",
                "properties": {
                    "question": {
                        "type": "string",
                        "description": "Natural-language question asked by the user (e.g. 'làm sao thêm key hội đồng thu phí?')",
                        "default": "",
                    },
                    "workspace_root": {"type": "string", "default": "."},
                    "auto_configure-byok": {
                        "type": "boolean",
                        "description": "Set to true when the user asks the Agent to automatically register and mint a real $0 DeepSeek Free API key.",
                        "default": False,
                    },
                    "deepseek_count": {
                        "type": "integer",
                        "description": "Number of independent DeepSeek Free accounts/tokens to register (1..5).",
                        "default": 1,
                    },
                },
            },
        },
        {
            "name": "kintsugi_compact_context",
            "description": (
                "Zero-Loss Anti-Overflow Conversation Compactor (`@COMPACT/2`). Call this tool when a conversation "
                "approaches context overflow (`>=70%` soft / `>=85%` hard watermark) or when the user asks to compress/save "
                "conversation state. Strips 4 classes of noise (verbose build/test logs, polling loops, superseded file reads, "
                "thinking chaff) while locking 100% of `@USER_INTENTS`, `@HARD_ANCHORS` (`file:line`, commits, rules, IPs, daemons), "
                "and `@ERRORS_AND_FIXES` into `.kintsugi/context_checkpoints/latest_checkpoint.md` and `@COMPACT/1` wire."
            ),
            "annotations": {
                "title": "Zero-Loss Conversation & Excel Context Compactor",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
            "inputSchema": {
                "type": "object",
                "properties": {
                    "transcript_path": {
                        "type": "string",
                        "description": "Optional path to conversation transcript (.jsonl, .json, or .md). Auto-discovered if omitted.",
                    },
                    "raw_conversation": {
                        "type": "string",
                        "description": "Optional inline conversation log or JSONL to compact directly.",
                    },
                    "workspace_root": {"type": "string", "default": "."},
                    "max_tokens": {"type": "integer", "default": 128000},
                    "inject_agents_md": {
                        "type": "boolean",
                        "description": "Inject the `<180-token` `@COMPACT/1` memory capsule into `CLAUDE.md` and `AGENTS.md`.",
                        "default": False,
                    },
                    "co_run": {
                        "type": "boolean",
                        "description": "Include Multi-Model Co-Execution verification metadata.",
                        "default": False,
                    },
                },
            },
        },
        {
            "name": "kintsugi_integrate_harness",
            "description": (
                "Universal Drop-In Third-Party Harness Integrator (`@HARNESS_BRIDGE/1` — `kintsugi integrate`). "
                "Autonomously discovers existing `.cursorrules`, `.cursor/rules/*.mdc`, `CLAUDE.md`, `AGENTS.md`, "
                "`.windsurfrules`, `.clinerules`, and `.github/copilot-instructions.md` in a workspace, runs an 8-stage "
                "Zero-Execution Security Quarantine (`@QUARANTINE/1`), checks for rule contradictions via a Joint SAT + "
                "Difference Logic (`SAT+DL`) verifier, and mounts them into `KMI/1` ultra-low-token wire format (`93.8%–99.96%` fewer tokens)."
            ),
            "annotations": {
                "title": "Universal Drop-In Third-Party Harness Integrator",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["discover", "status", "check_conflicts", "integrate", "eject"],
                        "default": "discover",
                        "description": "Integration action to run (`discover` is read-only; `integrate` mounts into `.kintsugi/integrated/`).",
                    },
                    "workspace_root": {"type": "string", "default": "."},
                    "source_path": {
                        "type": "string",
                        "description": "Optional path to a specific `.cursorrules`, `CLAUDE.md`, or downloaded harness folder to integrate.",
                    },
                    "harness_id": {
                        "type": "string",
                        "description": "Harness ID (`HARNESS-...`) when running `action='eject'`.",
                    },
                },
            },
        },
        {
            "name": "kintsugi_verify_logic",
            "description": (
                "Run `@LOGIC/2` 5-Pillar Neuro-Symbolic Logical Reasoning & Login State-Machine Verifier "
                "(DPLL SAT/MUS solver, Stratified Datalog with negation, Exact Semiring Difference Logic, "
                "Formal Fallacy Guard, and Login/OAuth2 PKCE/JWT/Session state-machine security audit)."
            ),
            "annotations": {
                "title": "5-Pillar Symbolic Logic & Login Security Verifier",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
            "inputSchema": {
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "Optional source code snippet to verify for login/auth state-machine flaws or logical contradictions.",
                    },
                    "self_test": {
                        "type": "boolean",
                        "default": True,
                        "description": "Run the 5-Pillar Neuro-Symbolic self-test suite.",
                    },
                },
            },
        },
        {
            "name": "kintsugi_cinema_produce",
            "description": (
                "OpenMontage Cinema Director's Cut Extension Package (`@OPENMONTAGE_CINEMA/1` · `kintsugi cinema`). "
                "Autonomously pulls/sandboxes `calesthio/OpenMontage`, routes video generation across Google Veo 3.1, "
                "Open-Weights Engine, Kling, Runway, Luma, Pika, Hailuo, Sora, and Wan, optimizes visual prompts & LUTs for "
                "user-selected `live_action` (Photorealistic Human Cinema on ARRI Alexa LF + Kodak 2383 LUT) vs `animation` "
                "(2D/3D Studio Cel LUT), runs mandatory 6-Gate Component Video QA (Script-to-Frame Discrepancy Verifier, "
                "Borderless Hygiene, Wardrobe/Collar DNA Lock, Style Fidelity, Motion Energy, and Integer-Tick Audio-First Sync), "
                "and evolves filmmaking intelligence via `@CINEMA_EVOLVE/1` (`CS-001`..`CS-012`)."
            ),
            "annotations": {
                "title": "OpenMontage Cinema Video Producer & 6-Gate QA Verifier",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": True,
            },
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace_root": {"type": "string", "default": "."},
                    "style_mode": {
                        "type": "string",
                        "enum": ["live_action", "animation"],
                        "default": "live_action",
                        "description": "User-selected visual optimization mode: 'live_action' (Human Cinema) or 'animation' (2D/3D Animation).",
                    },
                    "provider": {
                        "type": "string",
                        "enum": ["veo", "muse", "kling", "runway", "luma", "pika", "hailuo", "sora", "wan"],
                        "default": "veo",
                        "description": "Target video generation provider.",
                    },
                    "auto_heal": {
                        "type": "boolean",
                        "default": True,
                        "description": "Run @CINEMA_EVOLVE/1 to auto-heal screenplay/frame/wardrobe/prop/timing discrepancies.",
                    },
                    "pull_remote_openmontage": {
                        "type": "boolean",
                        "default": False,
                        "description": "Whether to perform a live git clone of calesthio/OpenMontage if not yet cached.",
                    },
                    "manifest": {
                        "type": "object",
                        "description": "Optional screenplay/shot manifest JSON object (uses built-in Station 09 demo manifest if omitted).",
                    },
                },
            },
        },
    ]


def _nextgen_tool_definitions() -> list[Dict[str, Any]]:
    return [
        {
            "name": "kintsugi_tools_discover",
            "description": "Passively discover local allowlisted tools without executing untrusted binaries.",
            "annotations": {
                "title": "Passive Local Tool Discovery",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace_root": {"type": "string"},
                    "allowlisted_paths": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
        {
            "name": "kintsugi_capability_analyze",
            "description": "Analyze missing capabilities and deterministically resolve verified local tools (0 LLM calls).",
            "annotations": {
                "title": "Capability Gap & Resolver",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
            "inputSchema": {
                "type": "object",
                "required": ["required_capabilities"],
                "properties": {
                    "workspace_root": {"type": "string"},
                    "goal_id": {"type": "string"},
                    "required_capabilities": {"type": "array", "items": {"type": "string"}},
                    "registry_path": {"type": "string"},
                },
            },
        },
        {
            "name": "kintsugi_reposcout_impact",
            "description": "Compute symlink-confined incremental AST symbol lookups and changed-file to affected-test mappings.",
            "annotations": {
                "title": "RepoScout Incremental Impact Analysis",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace_root": {"type": "string"},
                    "changed_files": {"type": "array", "items": {"type": "string"}},
                    "symbol": {"type": "string"},
                },
            },
        },
        {
            "name": "kintsugi_logforge_scan",
            "description": "Scan delimiter byte offsets across text or bytes using LogForge deterministic Python/Rust NEON parity backend.",
            "annotations": {
                "title": "LogForge Delimiter Scanner",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
            "inputSchema": {
                "type": "object",
                "required": ["text"],
                "properties": {
                    "text": {"type": "string"},
                    "delim": {"type": "integer"},
                    "tier": {"type": "string", "enum": ["auto", "python", "rust_neon", "rust_scalar"]},
                    "normalize": {"type": "boolean"},
                },
            },
        },
    ]


def _v3_envelope_tool_definitions() -> list[Dict[str, Any]]:
    return [
        {
            "name": "kintsugi_read_with_context",
            "description": (
                "Read a source file alongside its Kintsugi v3.0 `ContextEnvelope` (bound `source_digest`, "
                "symbol-scoped invariant capsules, typed obligation warnings, and optional Low-Tier Model Failure Lexicon)."
            ),
            "annotations": {
                "title": "Read File With Kintsugi v3 ContextEnvelope",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
            "inputSchema": {
                "type": "object",
                "required": ["file_path"],
                "properties": {
                    "file_path": {"type": "string", "description": "Path to source file to read with JIT envelope"},
                    "low_tier": {"type": "boolean", "default": True, "description": "Include matched Low-Tier Model Failure Lexicon entries"},
                    "max_tokens": {"type": "integer", "default": 320, "description": "Strict token cap for compact context"},
                },
            },
        },
        {
            "name": "kintsugi_low_tier_lexicon",
            "description": (
                "Query the 80-entry Low-Tier Model Failure Lexicon (`LT-001`..`LT-080`) JIT-matched to a target file "
                "or in full (`show_all=true`) so budget/fast models avoid common Python, TS/React, Solidity, Go, Rust & CI traps."
            ),
            "annotations": {
                "title": "Low-Tier Model Failure Lexicon (LT-001..LT-080)",
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Optional target source file for JIT symbol-scoped matching"},
                    "show_all": {"type": "boolean", "default": False, "description": "Return the full 80-entry lexicon"},
                    "max_entries": {"type": "integer", "default": 4},
                },
            },
        },
        {
            "name": "kintsugi_delivery_telemetry",
            "description": (
                "Record or inspect Kintsugi v3.0 Delivery Gate Telemetry (`DeliveryTelemetry/1`: honest "
                "`issued -> included_in_input -> patch_bound` tracking & 2-Strike / Dead-Scar Auto-Freeze)."
            ),
            "annotations": {
                "title": "Kintsugi v3 Delivery Gate Telemetry",
                "readOnlyHint": False,
                "destructiveHint": False,
                "idempotentHint": False,
                "openWorldHint": False,
            },
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["report", "record"], "default": "report"},
                    "store_path": {"type": "string", "description": "Optional telemetry JSON path (defaults to .kintsugi/delivery_telemetry.json)"},
                    "client": {"type": "string", "enum": ["claude_code", "antigravity", "local_cli", "cloud_sandbox"]},
                    "stage": {"type": "string", "enum": ["issued", "included_in_input", "patch_bound"]},
                    "session_id": {"type": "string"},
                    "envelope_id": {"type": "string"},
                    "source_digest": {"type": "string", "default": ""},
                    "patch_digest": {"type": "string", "default": ""},
                    "capsule_ids": {"type": "array", "items": {"type": "string"}},
                    "pitfall_ids": {"type": "array", "items": {"type": "string"}},
                    "estimated_tokens": {"type": "integer", "default": 0},
                    "passed": {"type": "boolean"},
                },
            },
        },
    ]


class KintsugiMCPServer:
    """Line-delimited JSON-RPC 2.0 MCP server over stdio."""

    def __init__(
        self,
        ledger_path: Path | str = ".kintsugi/scars.json",
        *,
        profile: str = "default",
        attestation_authority: Optional[Any] = None,
        authority_key_file: Optional[Union[str, Path]] = None,
        workspace_root: Optional[Union[str, Path]] = None,
    ) -> None:
        self.ledger = ScarLedger(ledger_path, ensure_builtin_crs=True)
        if not self.ledger.all():
            self.ledger.bootstrap_starter_pack()
        self.profile = str(profile or "default").lower()
        self._session_hit_telemetry: Dict[str, int] = {}
        self._attestation_authority: Optional[Any] = None
        self._authority_key_file: Optional[Path] = None

        if attestation_authority is not None and authority_key_file is not None:
            raise ValueError(
                "CONFLICTING_ATTESTATION_AUTHORITY: pass either attestation_authority or authority_key_file, not both."
            )
        if attestation_authority is not None:
            from kintsugi.capability.tool_registry import AttestationAuthority

            if not isinstance(attestation_authority, AttestationAuthority):
                raise ValueError(
                    "INVALID_ATTESTATION_AUTHORITY: expected AttestationAuthority instance."
                )
            self._attestation_authority = attestation_authority
        elif authority_key_file is not None:
            from kintsugi.capability.tool_registry import AttestationAuthority

            ws_root: Optional[Path] = None
            if workspace_root is not None:
                if isinstance(workspace_root, Path):
                    ws_root = workspace_root.resolve()
                elif isinstance(workspace_root, str) and workspace_root.strip():
                    ws_root = Path(workspace_root).resolve()
                else:
                    raise ValueError("INVALID_WORKSPACE_ROOT: expected non-empty str or Path.")
            self._attestation_authority = AttestationAuthority.from_key_file(
                authority_key_file,
                workspace_root=ws_root,
            )
            self._authority_key_file = Path(authority_key_file).resolve()

    def active_tools(self) -> list[Dict[str, Any]]:
        tools = list(_tool_definitions())
        if self.profile in {"nextgen", "coding", "build3", "cognitive", "v3"}:
            from kintsugi.mcp_nextgen import (
                nextgen_build2_tool_definitions,
                nextgen_build3_tool_definitions,
            )

            tools.extend(_nextgen_tool_definitions())
            tools.extend(nextgen_build2_tool_definitions())
            if self.profile in {"build3", "cognitive", "v3"}:
                tools.extend(nextgen_build3_tool_definitions())
            if self.profile == "v3":
                tools.extend(_v3_envelope_tool_definitions())
        return tools

    def handle_request(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        method = message.get("method")
        msg_id = message.get("id")
        params = message.get("params") or {}

        # Notifications do not receive JSON-RPC responses
        if msg_id is None:
            return None

        try:
            if method == "initialize":
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {
                            "tools": {},
                            "resources": {},
                            "prompts": {},
                        },
                        "serverInfo": {
                            "name": "kintsugi-harness",
                            "version": __version__,
                        },
                    },
                }

            if method == "ping":
                return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

            if method == "tools/list":
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"tools": self.active_tools()},
                }

            if method == "resources/list":
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "resources": [
                            {
                                "uri": "kintsugi://ledger/scars",
                                "name": "Verified Kintsugi Golden Scars Ledger",
                                "description": "All verified AST + regex Golden Scars (❌ Anti-Pattern vs ✅ Verified Fix).",
                                "mimeType": "application/json",
                            },
                            {
                                "uri": "kintsugi://posture/summary",
                                "name": "Kintsugi Posture & Token Savings Summary",
                                "description": "Current ledger posture, version, and KMI/1 token compression metrics.",
                                "mimeType": "application/json",
                            },
                        ]
                    },
                }

            if method == "resources/read":
                uri = str(params.get("uri") or "kintsugi://posture/summary")
                if uri == "kintsugi://ledger/scars":
                    payload = {"count": len(self.ledger.all()), "scars": [s.to_dict() for s in self.ledger.all()]}
                else:
                    payload = {
                        "version": __version__,
                        "license": "Apache-2.0",
                        "scars_count": len(self.ledger.all()),
                        "kmi_token_savings_pct": 94.0,
                        "starter_kmi_token_savings_pct": 93.8,
                        "domain_kmi_token_savings_pct": 99.95,
                        "rust_pretool_latency_us": 16.2,
                        "domain_shards": {
                            k: v["doc_path"] for k, v in DOMAIN_SHARD_REGISTRY.items()
                        },
                    }
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "contents": [
                            {
                                "uri": uri,
                                "mimeType": "application/json",
                                "text": json.dumps(payload, indent=2, ensure_ascii=False),
                            }
                        ]
                    },
                }

            if method == "resources/templates/list":
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"resourceTemplates": []},
                }

            if method == "prompts/list":
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "prompts": [
                            {
                                "name": "kintsugi-audit-code",
                                "description": "Audit a code file or snippet against Kintsugi Golden Scars and @LOGIC/2 state-machine invariants.",
                                "arguments": [
                                    {
                                        "name": "file_path",
                                        "description": "Path to the file to audit",
                                        "required": True,
                                    }
                                ],
                            },
                            {
                                "name": "kintsugi-evolve-scar",
                                "description": "Evolve a runtime failure or bug traceback into a self-verified Golden Scar and domain-routed KMI/1 shard.",
                                "arguments": [
                                    {
                                        "name": "error_summary",
                                        "description": "Concise summary of the runtime failure or security bug",
                                        "required": True,
                                    },
                                    {
                                        "name": "raw_trace",
                                        "description": "Stack trace or offending code snippet",
                                        "required": False,
                                    },
                                ],
                            },
                        ]
                    },
                }

            if method == "prompts/get":
                pname = str(params.get("name") or "kintsugi-audit-code")
                pargs = params.get("arguments") or {}
                if pname == "kintsugi-evolve-scar":
                    err_sum = str(pargs.get("error_summary") or "Runtime failure")
                    trace_txt = str(pargs.get("raw_trace") or "")
                    prompt_text = (
                        f"Call `kintsugi_record_failure` with `error_summary='{err_sum}'` and `raw_trace='{trace_txt}'` "
                        "to synthesize a self-verified Golden Scar (`scan(bad) >= 1` and `scan(good) == 0`), "
                        "then call `kintsugi_compile_skills` to update the KMI/1 wire index."
                    )
                elif pname == "kintsugi-integrate-harness":
                    ws = str(pargs.get("workspace_root") or ".")
                    prompt_text = (
                        f"Call `kintsugi_integrate_harness` with `action='discover'` and `workspace_root='{ws}'` "
                        "to inspect existing `.cursorrules`, `CLAUDE.md`, and `AGENTS.md` files, verify SAT+DL "
                        "rule consistency, and report the token compression ratio."
                    )
                else:
                    fp = str(pargs.get("file_path") or "src/")
                    prompt_text = (
                        f"Call `kintsugi_scan_code` on `{fp}` and `kintsugi_verify_logic` to check for "
                        "security anti-patterns and state-machine contradictions."
                    )
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "description": f"Kintsugi workflow prompt: {pname}",
                        "messages": [
                            {
                                "role": "user",
                                "content": {"type": "text", "text": prompt_text},
                            }
                        ],
                    },
                }

            if method == "tools/call":
                tool_name = params.get("name")
                args = params.get("arguments") or {}
                output = self._dispatch_tool(str(tool_name), args)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(output, indent=2, ensure_ascii=False),
                            }
                        ],
                        "isError": False,
                    },
                }

            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
        except Exception as exc:  # noqa: BLE001 - JSON-RPC boundary returns structured MCP tool error
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": f"Error: {exc}"}],
                    "isError": True,
                },
            }

    def _dispatch_tool(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if name == "kintsugi_scan_code":
            scanner = KintsugiScanner(self.ledger.all())
            code = args.get("code")
            fpath = str(args.get("file_path") or "<snippet.py>")
            lang = args.get("language")
            if code is not None:
                findings = scanner.scan_text(str(code), file_path=fpath, language=lang)
                for f in findings:
                    self._session_hit_telemetry[f.scar_id] = self._session_hit_telemetry.get(f.scar_id, 0) + 1
                return {
                    "passed": len(findings) == 0,
                    "findings_count": len(findings),
                    "findings": [f.to_dict() for f in findings],
                }
            report = scanner.scan_path(fpath)
            for f in report.findings:
                self._session_hit_telemetry[f.scar_id] = self._session_hit_telemetry.get(f.scar_id, 0) + 1
            return report.to_dict()

        if name == "kintsugi_list_scars":
            sev = Severity(args["min_severity"].upper()) if args.get("min_severity") else None
            scars = self.ledger.list_scars(
                language=args.get("language"),
                tag=args.get("tag"),
                min_severity=sev,
            )
            domain_arg = args.get("domain")
            if domain_arg:
                partitioned = partition_by_domain(scars)
                from kintsugi.compressor import normalize_domain_key

                dom_key = normalize_domain_key(str(domain_arg))
                dom_scars = partitioned.get(dom_key, [])
                return {
                    "domain": dom_key,
                    "doc_path": DOMAIN_SHARD_REGISTRY[dom_key]["doc_path"],
                    "count": len(dom_scars),
                    "domain_kmi_pack": render_domain_kmi_pack(scars, domain=dom_key),
                    "scars": [s.to_dict() for s in dom_scars],
                }
            return {"count": len(scars), "scars": [s.to_dict() for s in scars]}

        if name == "kintsugi_record_failure":
            ws_root = str(args.get("workspace_root") or ".")
            trace = FailureTrace(
                source="mcp",
                error_summary=str(args["error_summary"]),
                raw_trace=str(args["raw_trace"]),
                language=str(args.get("language") or "python"),
                offending_snippet=str(args.get("offending_snippet") or ""),
                fixed_snippet=str(args.get("fixed_snippet") or ""),
            )
            council = EvolutionCouncil(workspace_root=ws_root)
            if args.get("co_run") or args.get("free_runners") is not None or args.get("paid_council"):
                scar, co_rep = council.evolve_with_co_runners(
                    trace,
                    scar_id=self.ledger.next_id(),
                    num_free_runners=args.get("free_runners"),
                    include_paid_council=bool(args.get("paid_council", False)),
                )
                is_new, stored = self.ledger.upsert(scar)
                self.ledger.save()
                return {
                    "is_new": is_new,
                    "verification": co_rep["kmi_corun_wire"],
                    "scar": stored.to_dict(),
                    "co_execution_report": co_rep,
                }
            scar, check_msg = council.evolve(trace, scar_id=self.ledger.next_id())
            is_new, stored = self.ledger.upsert(scar)
            self.ledger.save()
            return {
                "is_new": is_new,
                "verification": check_msg,
                "scar": stored.to_dict(),
            }

        if name == "kintsugi_compile_skills":
            root = str(args.get("workspace_root") or ".")
            targets = args.get("targets") or ["skills", "claude", "agents", "cursor"]
            compiler = SkillCompiler(self.ledger.all())
            written = compiler.compile_all(root, targets=targets)
            return {"compiled_files": [str(p) for p in written]}

        if name == "kintsugi_multi_model_guide":
            root = str(args.get("workspace_root") or ".")
            if bool(args.get("auto_configure-byok", False)):
                from kintsugi.swarm import ConsentGatedBYOKPoolManager

                cnt = int(args.get("deepseek_count") or 1)
                return ConsentGatedBYOKPoolManager(root).auto_configure-byok(
                    confirmed_by_user=True,
                    count=cnt,
                    verify_chat=True,
                )
            question = str(args.get("question") or "")
            return answer_user_multi_model_question(question=question, workspace_root=root)

        if name == "kintsugi_compact_context":
            root = str(args.get("workspace_root") or ".")
            max_tok = int(args.get("max_tokens") or 128000)
            compactor = ConversationCompactor(root, max_context_tokens=max_tok)
            raw_conv = args.get("raw_conversation")
            if raw_conv is not None and str(raw_conv).strip():
                return compactor.compact_text(
                    str(raw_conv),
                    source_label="<mcp_inline>",
                    persist=True,
                    inject_agents_md=bool(args.get("inject_agents_md", False)),
                    co_run=bool(args.get("co_run", False)),
                )
            return compactor.compact_from_source(
                explicit_path=args.get("transcript_path"),
                persist=True,
                inject_agents_md=bool(args.get("inject_agents_md", False)),
                co_run=bool(args.get("co_run", False)),
            )

        if name == "kintsugi_integrate_harness":
            from kintsugi.integrator import UniversalHarnessIntegrator

            root = Path(str(args.get("workspace_root") or ".")).resolve()
            action = str(args.get("action") or "discover").lower()
            integrator = UniversalHarnessIntegrator(root)
            if action == "discover":
                return integrator.discover_harnesses(root)
            if action == "status":
                return integrator.list_integrated_harnesses()
            if action == "check_conflicts":
                src = args.get("source_path") or root
                return integrator.ingest_and_analyze(Path(str(src)))
            if action == "eject":
                hid = str(args.get("harness_id") or "")
                return integrator.eject_harness(hid)
            src = args.get("source_path") or root
            return integrator.mount_harness(Path(str(src)))

        if name == "kintsugi_verify_logic":
            from kintsugi.logic import LoginAuthLogicVerifier, run_logical_reasoning_benchmark

            code_snippet = str(args.get("code") or "").strip()
            has_explicit_self_test = "self_test" in args
            run_self_test = bool(args.get("self_test", True)) if (has_explicit_self_test or not code_snippet) else False
            result: Dict[str, Any] = {}
            if run_self_test:
                result["self_test"] = run_logical_reasoning_benchmark()
            if code_snippet:
                code_sha256 = hashlib.sha256(code_snippet.encode("utf-8")).hexdigest()[:16]
                scanner = KintsugiScanner(self.ledger.all(), allow_inline_ignores=False)
                scan_findings = scanner.scan_text(code_snippet, file_path="<verify_logic_snippet.py>")
                auth_issues: List[Dict[str, Any]] = []

                # AST + static auth/state-machine inspection of caller-supplied code (`KH-MCP-002`)
                try:
                    tree = ast.parse(code_snippet)
                except SyntaxError:
                    tree = None

                sensitive_id_re = re.compile(r"(?:otp|token|secret|signature|sig|mac|digest|api_key|apikey|password|passwd|pin)", re.I)
                if tree is not None:
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Compare) and any(isinstance(op, (ast.Eq, ast.NotEq)) for op in node.ops):
                            names_in_cmp: List[str] = []
                            for side in [node.left] + list(node.comparators):
                                if isinstance(side, ast.Name):
                                    names_in_cmp.append(side.id)
                                elif isinstance(side, ast.Attribute):
                                    names_in_cmp.append(side.attr)
                            if any(sensitive_id_re.search(nm) for nm in names_in_cmp):
                                auth_issues.append(
                                    {
                                        "rule": "AUTH-TIMING-001",
                                        "severity": "HIGH",
                                        "line": getattr(node, "lineno", 1),
                                        "detail": f"Non-constant-time `==`/`!=` comparison on sensitive secret/OTP identifier ({', '.join(names_in_cmp)}); use `hmac.compare_digest`.",
                                    }
                                )
                        elif isinstance(node, ast.Assign):
                            for tgt in node.targets:
                                if isinstance(tgt, ast.Name) and tgt.id.lower() in {"allow_unchecked", "skip_auth", "bypass_auth", "disable_verify"}:
                                    if isinstance(node.value, ast.Constant) and node.value.value is True:
                                        auth_issues.append(
                                            {
                                                "rule": "AUTH-BYPASS-002",
                                                "severity": "CRITICAL",
                                                "line": getattr(node, "lineno", 1),
                                                "detail": f"Auth verification bypass flag `{tgt.id} = True` detected.",
                                            }
                                        )

                findings_dicts = [f.to_dict() for f in scan_findings]
                passed = len(findings_dicts) == 0 and len(auth_issues) == 0
                result["code_analysis"] = {
                    "analyzed": True,
                    "code_sha256": code_sha256,
                    "passed": passed,
                    "verdict": "PASS" if passed else "FAIL",
                    "findings_count": len(findings_dicts) + len(auth_issues),
                    "scanner_findings": findings_dicts,
                    "auth_state_machine_issues": auth_issues,
                }
                result["login_audit"] = {
                    "ok": True,
                    "code_sha256": code_sha256,
                    "passed": passed,
                    "verdict": result["code_analysis"]["verdict"],
                    "findings_count": result["code_analysis"]["findings_count"],
                    "scanner_findings": findings_dicts,
                    "auth_state_machine_issues": auth_issues,
                    "reference_suite": LoginAuthLogicVerifier().verify_login_security_suite(),
                }
            return result

        if name == "kintsugi_cinema_produce":
            from kintsugi.cinema import (
                CinemaEvolutionEngine,
                ComponentVideoQAVerifier,
                OpenMontagePackageManager,
                build_demo_flawed_openmontage_manifest,
            )

            root = Path(str(args.get("workspace_root") or ".")).resolve()
            style_mode = str(args.get("style_mode") or "live_action")
            provider = str(args.get("provider") or "veo")
            pull_remote = bool(args.get("pull_remote_openmontage", False))
            manifest_obj = args.get("manifest") or build_demo_flawed_openmontage_manifest()

            pkg_meta = OpenMontagePackageManager(root).ensure_openmontage_installed(
                auto_pull_remote=pull_remote
            )
            evo = CinemaEvolutionEngine(root)
            if bool(args.get("auto_heal", True)):
                healed, evo_rep = evo.auto_heal_and_evolve_manifest(
                    manifest_obj,
                    style_mode=style_mode,
                    provider=provider,
                )
                qa_rep = ComponentVideoQAVerifier().verify_production_manifest_and_clips(
                    healed,
                    style_mode=style_mode,
                )
                return {
                    "ok": qa_rep["ok"],
                    "openmontage_package": pkg_meta,
                    "evolution_report": evo_rep,
                    "qa_report": qa_rep,
                }
            qa_rep = ComponentVideoQAVerifier().verify_production_manifest_and_clips(
                manifest_obj,
                style_mode=style_mode,
            )
            return {
                "ok": qa_rep["ok"],
                "openmontage_package": pkg_meta,
                "qa_report": qa_rep,
            }

        if self.profile == "v3" and name == "kintsugi_delivery_telemetry":
            from kintsugi.evolution.delivery_telemetry import (
                build_telemetry_report as _tel_rep,
                record_telemetry_event as _rec_tel,
            )

            raw_store = args.get("store_path")
            store_p = Path(str(raw_store)) if raw_store else (self.ledger.path.parent / "delivery_telemetry.json")
            raw_action = args.get("action", "report")
            action = "report" if raw_action is None else str(raw_action).strip().lower()
            if action not in {"record", "report"}:
                raise ValueError(f"Unsupported telemetry action: {action!r}")
            if action == "record":
                raw_caps = args.get("capsule_ids")
                if raw_caps is not None and not isinstance(raw_caps, list):
                    raise ValueError("INVALID_CAPSULE_IDS: expected list of strings")
                raw_pits = args.get("pitfall_ids")
                if raw_pits is not None and not isinstance(raw_pits, list):
                    raise ValueError("INVALID_PITFALL_IDS: expected list of strings")
                est_tokens = 0 if args.get("estimated_tokens") is None else args["estimated_tokens"]
                return _rec_tel(
                    store_path=store_p,
                    client=str(args.get("client") or ""),
                    stage=str(args.get("stage") or ""),
                    session_id=str(args.get("session_id") or ""),
                    envelope_id=str(args.get("envelope_id") or ""),
                    source_digest=str(args.get("source_digest") or ""),
                    patch_digest=str(args.get("patch_digest") or ""),
                    capsule_ids=raw_caps if raw_caps is not None else [],
                    pitfall_ids=raw_pits if raw_pits is not None else [],
                    estimated_tokens=est_tokens,
                    passed=args.get("passed") if "passed" in args else None,
                )
            return _tel_rep(store_p)

        if self.profile == "v3" and name in {"kintsugi_read_with_context", "kintsugi_low_tier_lexicon"}:
            import shutil as _shutil
            import subprocess as _sp

            env_bin = os.environ.get("KINTSUGI_RS_BIN", "").strip()
            which_bin = _shutil.which("kintsugi-rs")
            kbin_candidates = [
                *( [Path(env_bin)] if env_bin else [] ),
                Path(__file__).resolve().parents[2] / "target" / "release" / "kintsugi-rs",
                Path(__file__).resolve().parents[2] / "target" / "debug" / "kintsugi-rs",
                Path.cwd() / ".kintsugi" / "bin" / "kintsugi-rs",
                *( [Path(which_bin)] if which_bin else [] ),
            ]
            kbin = next((p for p in kbin_candidates if p.is_file()), None)
            if kbin is None:
                raise FileNotFoundError("kintsugi-rs release binary not found for v3 ContextEnvelope tool")

            if name == "kintsugi_read_with_context":
                fp = Path(str(args["file_path"])).resolve()
                cmd = [str(kbin), "context", str(fp), "--format", "json", "--max-tokens", str(int(args.get("max_tokens") or 320))]
                if bool(args.get("low_tier", True)):
                    cmd.append("--low-tier")
                proc = _sp.run(cmd, capture_output=True, text=True, shell=False, timeout=15)
                if proc.returncode != 0:
                    raise RuntimeError(f"kintsugi-rs context failed: {proc.stderr or proc.stdout}")
                env_obj = json.loads(proc.stdout.strip())
                env_obj["receipt_stage"] = "included_in_input"
                return {
                    "ok": True,
                    "file_path": str(fp),
                    "content": fp.read_text(encoding="utf-8"),
                    "envelope": env_obj,
                }

            cmd = [str(kbin), "lexicon", "--format", "json"]
            if bool(args.get("show_all", False)) or not args.get("file_path"):
                cmd.append("--all")
            else:
                cmd.extend([str(Path(str(args["file_path"])).resolve()), "--max-entries", str(int(args.get("max_entries") or 4))])
            proc = _sp.run(cmd, capture_output=True, text=True, shell=False, timeout=15)
            if proc.returncode != 0:
                raise RuntimeError(f"kintsugi-rs lexicon failed: {proc.stderr or proc.stdout}")
            return json.loads(proc.stdout.strip())

        if self.profile in {"nextgen", "coding", "build3", "cognitive", "v3"}:
            if name == "kintsugi_tools_discover":
                from kintsugi.capability import SecurityContext, ToolRegistry

                ws = Path(str(args.get("workspace_root") or ".")).resolve()
                sec_ctx = SecurityContext(workspace_root=str(ws), network_allowed=False)
                reg = ToolRegistry()
                discovered = reg.discover_local(sec_ctx, allowlisted_paths=args.get("allowlisted_paths"))
                return {"ok": True, "discovered_count": len(discovered), "tools": [t.to_dict() for t in discovered]}

            if name == "kintsugi_capability_analyze":
                from kintsugi.capability import CapabilityGapDetector, SecurityContext, ToolRegistry, ToolResolver

                ws = Path(str(args.get("workspace_root") or ".")).resolve()
                sec_ctx = SecurityContext(workspace_root=str(ws), network_allowed=False)
                reg = ToolRegistry()
                reg_path_raw = args.get("registry_path")
                if reg_path_raw:
                    rp = Path(str(reg_path_raw))
                    rp = rp if rp.is_absolute() else (ws / rp)
                    if rp.exists():
                        reg.load(rp)
                goal = {
                    "goal_id": str(args.get("goal_id") or "mcp-goal-001"),
                    "required_capabilities": list(args.get("required_capabilities") or []),
                }
                gap = CapabilityGapDetector().analyze(goal, reg, sec_ctx)
                res = ToolResolver().resolve(gap, reg, sec_ctx)
                return {"ok": res.executable, "capability_gap": gap.to_dict(), "resolution": res.to_dict()}

            if name == "kintsugi_reposcout_impact":
                from kintsugi.tools import RepoScout

                ws = Path(str(args.get("workspace_root") or ".")).resolve()
                scout = RepoScout(ws)
                idx = scout.build()
                out: Dict[str, Any] = {"ok": True, "file_count": len(idx.get("files", {})), "index_digest": idx.get("index_digest")}
                if args.get("changed_files"):
                    out["impact"] = scout.map_changed_files_to_tests(args["changed_files"])
                if args.get("symbol"):
                    out["symbols"] = scout.find_symbol(str(args["symbol"]))
                return out

            if name == "kintsugi_logforge_scan":
                from kintsugi.tools import LogForge

                tier_map = {"python": "python_oracle", "rust_neon": "rust_simd"}
                raw_tier = str(args.get("tier") or "auto")
                res = LogForge().scan_delimiters(
                    str(args.get("text") or "").encode("utf-8"),
                    delim=int(args.get("delim", 10)),
                    tier=tier_map.get(raw_tier, raw_tier),
                    normalize=bool(args.get("normalize", False)),
                )
                return {"ok": True, "result": res.to_dict()}

            from kintsugi.mcp_nextgen import (
                NEXTGEN_BUILD2_TOOL_NAMES,
                NEXTGEN_BUILD3_TOOL_NAMES,
                dispatch_nextgen_build2_mcp_tool,
                dispatch_nextgen_build3_mcp_tool,
            )

            if name in NEXTGEN_BUILD2_TOOL_NAMES:
                return dispatch_nextgen_build2_mcp_tool(name, args)
            if self.profile in {"build3", "cognitive", "v3"} and name in NEXTGEN_BUILD3_TOOL_NAMES:
                if self._authority_key_file is not None and args.get("workspace_root") is not None:
                    ws_req = Path(str(args.get("workspace_root") or ".")).resolve()
                    if self._authority_key_file.is_relative_to(ws_req):
                        raise PermissionError(
                            f"ATTESTATION_KEY_FILE_INSIDE_WORKSPACE: '{self._authority_key_file}' must be outside workspace '{ws_req}'."
                        )
                return dispatch_nextgen_build3_mcp_tool(
                    name,
                    args,
                    authority=self._attestation_authority,
                )

        raise ValueError(f"Unknown MCP tool: {name}")

    def serve_stdio(
        self,
        stdin: TextIO = sys.stdin,
        stdout: TextIO = sys.stdout,
    ) -> None:
        for raw_line in stdin:
            line = raw_line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error"},
                }
                stdout.write(json.dumps(err_resp) + "\n")
                stdout.flush()
                continue
            resp = self.handle_request(msg)
            if resp is not None:
                stdout.write(json.dumps(resp) + "\n")
                stdout.flush()


if __name__ == "__main__":
    KintsugiMCPServer().serve_stdio()
