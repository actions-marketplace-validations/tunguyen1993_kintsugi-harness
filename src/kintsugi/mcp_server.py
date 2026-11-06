"""Zero-dependency Model Context Protocol (MCP) stdio JSON-RPC 2.0 server (`kintsugi mcp`)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional, TextIO

from kintsugi import __version__
from kintsugi.compactor import ConversationCompactor
from kintsugi.compiler import SkillCompiler
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
            "inputSchema": {
                "type": "object",
                "properties": {
                    "language": {"type": "string"},
                    "tag": {"type": "string"},
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
                "Primary + 2..5 Free Models on Pro tier ($15/$19), and Primary + Free Models + BYOK Paid Frontier Council on Enterprise Pro ($29)."
            ),
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
                        "description": "Include user-supplied BYOK Paid Frontier Council seats (requires Enterprise Complete Pro $29)",
                        "default": False,
                    },
                },
            },
        },
        {
            "name": "kintsugi_compile_skills",
            "description": "Compile `.kintsugi/scars.json` into `.claude/skills/*/SKILL.md`, `CLAUDE.md`, `AGENTS.md`, and `.cursor/rules/`.",
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
                "Token Harvester. Call this tool whenever the user asks how to use Multi-Model Co-Execution, how many Free models "
                "their edition supports (Free=1, Pro=2..5, Enterprise=5+6 BYOK Paid), how to add their own "
                "API keys (`BYOK`) for the Paid Frontier Council, or pass `auto_register_deepseek_free=true` to autonomously "
                "register a disposable mail.tm inbox and mint a live $0 DeepSeek-V4.1-Flash (262K) API key."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "question": {
                        "type": "string",
                        "description": "Natural-language question asked by the user (e.g. 'làm sao thêm key hội đồng thu phí?')",
                        "default": "",
                    },
                    "workspace_root": {"type": "string", "default": "."},
                    "auto_register_deepseek_free": {
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
                "Zero-Loss Anti-Overflow Conversation Compactor (`@COMPACT/1`). Call this tool when a conversation "
                "approaches context overflow (`>=70%` soft / `>=85%` hard watermark) or when the user asks to compress/save "
                "conversation state. Strips 4 classes of noise (verbose build/test logs, polling loops, superseded file reads, "
                "thinking chaff) while locking 100% of `@USER_INTENTS`, `@HARD_ANCHORS` (`file:line`, commits, rules, IPs, daemons), "
                "and `@ERRORS_AND_FIXES` into `.kintsugi/context_checkpoints/latest_checkpoint.md` and `@COMPACT/1` wire."
            ),
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
    ]


class KintsugiMCPServer:
    """Line-delimited JSON-RPC 2.0 MCP server over stdio."""

    def __init__(self, ledger_path: Path | str = ".kintsugi/scars.json") -> None:
        self.ledger = ScarLedger(ledger_path)
        if not self.ledger.all():
            self.ledger.bootstrap_starter_pack()

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
                    "result": {"tools": _tool_definitions()},
                }

            if method == "resources/list":
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"resources": []},
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
                    "result": {"prompts": []},
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
                self.ledger.record_hits([f.scar_id for f in findings])
                return {
                    "passed": len(findings) == 0,
                    "findings_count": len(findings),
                    "findings": [f.to_dict() for f in findings],
                }
            report = scanner.scan_path(fpath)
            self.ledger.record_hits([f.scar_id for f in report.findings])
            return report.to_dict()

        if name == "kintsugi_list_scars":
            sev = Severity(args["min_severity"].upper()) if args.get("min_severity") else None
            scars = self.ledger.list_scars(
                language=args.get("language"),
                tag=args.get("tag"),
                min_severity=sev,
            )
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
            if bool(args.get("auto_register_deepseek_free", False)):
                from kintsugi.swarm import ConsentGatedFreePoolManager

                cnt = int(args.get("deepseek_count") or 1)
                return ConsentGatedFreePoolManager(root).auto_register_deepseek_free(
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
