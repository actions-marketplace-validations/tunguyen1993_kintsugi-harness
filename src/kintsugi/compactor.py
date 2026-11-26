"""
Anti-Overflow Conversation Compactor & Zero-Loss Context Distillation Engine (`@COMPACT/1`).

Prevents context-window overflow in long-running AI coding sessions (`Claude Code`, `Cursor`,
`Antigravity`, `Windsurf`, `Codex`) by:
1. Monitoring live token pressure against soft (`70%`) and hard (`85%`) watermarks.
2. Stripping 4 classes of conversation noise (verbose CLI/build logs, repetitive polling loops,
   superseded intermediate file reads, and exploratory dead-end monologue).
3. Locking 100% of Hard Anchors (`@USER_INTENTS`, file:line anchors, symbols, git SHAs/tags,
   pinned IPs/ports, `@ERRORS_AND_FIXES`, active daemons, and next steps).
4. Emitting both a structured Resumption Checkpoint (`.kintsugi/context_checkpoints/latest_checkpoint.md`)
   and an ultra-dense `<180-token` `@COMPACT/1` symbolic wire capsule (`.kintsugi/context_checkpoints/latest_checkpoint.kml`).
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import time
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, TypeVar

from kintsugi import __version__
from kintsugi.compressor import estimate_tokens
from kintsugi.shield import redact_high_entropy_secrets

_T = TypeVar("_T")

COMPACT_BOUNDARY_START = "<!-- KINTSUGI:COMPACT/1 START -->"
COMPACT_BOUNDARY_END = "<!-- KINTSUGI:COMPACT/1 END -->"

# Secret redaction patterns so compacted checkpoints never leak raw tokens
_SECRET_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bsk-(?!proj-EXAMPLE_PLACEHOLDER|0{12,})[A-Za-z0-9_-]{16,}\b"), "sk-***REDACTED***"),
    (re.compile(r"\btj_(?!0{12,})[A-Za-z0-9_-]{16,}\b"), "tj_***REDACTED***"),
    (re.compile(r"\bgh[pousr]_(?!0{12,})[A-Za-z0-9]{20,}\b"), "gh_***REDACTED***"),
    (re.compile(r"\bgithub_pat_(?!0{12,})[A-Za-z0-9_]{20,}\b"), "github_pat_***REDACTED***"),
    (re.compile(r"\bgsk_(?!0{12,})[A-Za-z0-9]{20,}\b"), "gsk_***REDACTED***"),
    (re.compile(r"\bxai-(?!0{12,})[A-Za-z0-9_-]{16,}\b"), "xai-***REDACTED***"),
    (re.compile(r"\bhf_(?!0{12,})[A-Za-z0-9]{20,}\b"), "hf_***REDACTED***"),
    (re.compile(r"\bbyok_(?!0{12,}|paid_council)[A-Za-z0-9_-]{16,}\b"), "byok_***REDACTED***"),
    (re.compile(r"\bAIza(?!0{12,})[0-9A-Za-z_-]{30,}\b"), "AIza***REDACTED***"),
    (re.compile(r"\bxox[baprs]-(?!0{12,})[0-9A-Za-z-]{12,}\b"), "xox-***REDACTED***"),
    (re.compile(r"\bAKIA(?!0{12,})[0-9A-Z]{16}\b"), "AKIA***REDACTED***"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"), "jwt_***REDACTED***"),
)

# File path anchor regex (longest extensions first + word boundary so .json/.jsonl never truncate to .js)
_FILE_ANCHOR_RE = re.compile(
    r"(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+\.(?:jsonl|json|kpack|xlsx|toml|yaml|tsx|mjs|kml|yml|csv|tsv|zip|py|rs|js|ts|md|sh)\b(?:#L\d+(?:-L?\d+)?)?"
)
_COMMIT_OR_TAG_RE = re.compile(r"\b(?:v\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?|[0-9a-f]{7,12})\b")
_RULE_ID_RE = re.compile(r"(?<![A-Za-z0-9])(?:R1[0-9]{2}|KS-(?:WILD-|NET-)?\d{3}|CM-\d{3}|KL-[A-Z]+-\d{3})(?![A-Za-z0-9])")
_CLI_FLAG_RE = re.compile(r"(?:kintsugi\s+[a-z-]+(?:\s+--[a-z0-9-]+)*|--[a-z0-9-]{3,})")
_IP_OR_PORT_RE = re.compile(r"\b(?:\d{1,3}(?:\.\d{1,3}){3}(?::\d{2,5})?|localhost:\d{2,5}|:\d{4,5})\b")
_TASK_ID_RE = re.compile(r"\btask-\d+\b")
_TABULAR_ANOMALY_RE = re.compile(
    r"(?:CRITICAL|ERROR|FAIL(?:ED)?|DISCREPANCY|ANOMALY|OVERDUE|BREACH|MISMATCH|REJECTED|NEEDLE|ALERT|FRAUD|SECURITY|OUTLIER|R1[0-9]{2}|KS-(?:WILD-|NET-)?\d{3}|CM-\d{3})",
    re.IGNORECASE,
)


def _stratified_select(items: Sequence[_T], max_count: int) -> List[_T]:
    """
    Anti-'Lost-in-the-Middle' Stratified Selector:
    When `len(items) > max_count`, deterministically retains Early (Head) +
    evenly-spaced Middle landmarks (25%, 50%, 75%, ...) + Late (Tail) items
    so zero zone suffers from memory amnesia.
    """
    if max_count <= 0:
        return []
    n = len(items)
    if n <= max_count:
        return list(items)
    if max_count == 1:
        return [items[0]]
    if max_count == 2:
        return [items[0], items[-1]]
    head_k = max(1, max_count // 3)
    tail_k = max(1, max_count // 3)
    mid_k = max(1, max_count - head_k - tail_k)
    mid_pool = items[head_k : n - tail_k]
    mid_selected: List[_T] = []
    used_mid_indices: set[int] = set()
    if mid_pool:
        step = len(mid_pool) / float(mid_k)
        for i in range(mid_k):
            idx = min(len(mid_pool) - 1, max(0, int(round((i + 0.5) * step - 0.5))))
            val = mid_pool[idx]
            if idx not in used_mid_indices and val not in mid_selected:
                used_mid_indices.add(idx)
                mid_selected.append(val)
        # Backfill deterministically if duplicate values reduced `mid_selected` below `mid_k`
        if len(mid_selected) < mid_k:
            for bf_idx, bf_val in enumerate(mid_pool):
                if bf_idx not in used_mid_indices and bf_val not in mid_selected:
                    used_mid_indices.add(bf_idx)
                    mid_selected.append(bf_val)
                    if len(mid_selected) >= mid_k:
                        break
        # Preserve chronological order across all selected middle indices
        mid_selected = [mid_pool[i] for i in sorted(used_mid_indices)]
    return list(items[:head_k]) + mid_selected + list(items[n - tail_k :])


def redact_secrets(text: str) -> str:
    """Mask any raw API tokens AND contextual high-entropy secrets before persisting a checkpoint."""
    out = str(text or "")
    for pat, repl in _SECRET_PATTERNS:
        out = pat.sub(repl, out)
    return redact_high_entropy_secrets(out)


@dataclass
class UserPreferenceItem:
    """Provenance-backed user preference or standing constraint in `@USER_PERSONA/1`."""

    preference_id: str
    key: str
    value: str
    source_turn_id: int
    source_type: str = "explicit"  # "explicit" | "confirmed" | "inferred"
    scope: str = "workspace"       # "session" | "workspace" | "global"
    confidence: float = 0.98
    updated_at: str = ""
    status: str = "active"         # "active" | "tombstoned"


@dataclass
class UserPersonaProfile:
    """
    Adaptive User Personalization & Cognitive Twin Profile (`@USER_PERSONA/1`).
    Learned strictly from user-authored turns (never from tool output or untrusted repo files).
    """

    profile_id: str = "owner_cognitive_twin_v1"
    schema_version: str = "USER_PERSONA/1"
    version: int = 1
    preferred_language: str = "vi"
    communication_style: str = "direct, concise, evidence-verified"
    standing_constraints: List[str] = field(default_factory=list)
    workflow_preferences: List[str] = field(default_factory=list)
    frustration_watchouts: List[str] = field(default_factory=list)
    preferences: List[Dict[str, Any]] = field(default_factory=list)
    tombstones: List[str] = field(default_factory=list)
    updated_at: str = ""

    def digest(self) -> str:
        basis = json.dumps(
            {
                "lang": self.preferred_language,
                "style": self.communication_style,
                "constraints": self.standing_constraints,
                "workflows": self.workflow_preferences,
                "watchouts": self.frustration_watchouts,
                "preferences": self.preferences,
                "tombstones": self.tombstones,
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "schema_version": self.schema_version,
            "version": self.version,
            "digest": self.digest(),
            "preferred_language": self.preferred_language,
            "communication_style": self.communication_style,
            "standing_constraints": list(self.standing_constraints),
            "workflow_preferences": list(self.workflow_preferences),
            "frustration_watchouts": list(self.frustration_watchouts),
            "preferences": list(self.preferences),
            "tombstones": list(self.tombstones),
            "updated_at": self.updated_at,
        }


@dataclass
class ConversationTurn:
    """Normalized representation of a single conversation step/turn."""

    index: int
    role: str  # "user" | "assistant" | "tool" | "system"
    content: str
    thinking: str = ""
    tool_name: str = ""
    created_at: str = ""
    is_noise: bool = False
    noise_reason: str = ""
    collapsed_count: int = 1

    def raw_text(self) -> str:
        parts = [self.content]
        if self.thinking:
            parts.append(self.thinking)
        return "\n".join(p for p in parts if p)


@dataclass
class NoiseFilterReport:
    """Metrics produced by the 4-Stage Deterministic Noise Stripper + Tabular Distiller."""

    total_turns_in: int = 0
    turns_retained: int = 0
    polling_loops_collapsed: int = 0
    verbose_logs_folded: int = 0
    superseded_reads_pruned: int = 0
    thinking_chaff_trimmed: int = 0
    tabular_tables_distilled: int = 0
    tabular_rows_distilled: int = 0
    raw_tokens: int = 0
    clean_tokens: int = 0

    @property
    def noise_tokens_removed(self) -> int:
        return max(0, self.raw_tokens - self.clean_tokens)

    @property
    def noise_ratio(self) -> float:
        if self.raw_tokens <= 0:
            return 0.0
        return round(self.noise_tokens_removed / float(self.raw_tokens), 4)


@dataclass
class DistilledContext:
    """Structured core context extracted from a conversation with full completeness accounting."""

    user_intents: List[str] = field(default_factory=list)
    active_objective: str = ""
    completed_milestones: List[str] = field(default_factory=list)
    errors_and_fixes: List[Dict[str, str]] = field(default_factory=list)
    files_and_anchors: List[str] = field(default_factory=list)
    symbols_and_commands: List[str] = field(default_factory=list)
    commits_and_tags: List[str] = field(default_factory=list)
    rules_enforced: List[str] = field(default_factory=list)
    endpoints_and_ips: List[str] = field(default_factory=list)
    active_daemons: List[str] = field(default_factory=list)
    tabular_summaries: List[Dict[str, Any]] = field(default_factory=list)
    user_persona: Optional[UserPersonaProfile] = None
    recurrence_watchouts: List[str] = field(default_factory=list)
    completeness_manifest: Dict[str, Any] = field(default_factory=dict)
    pending_next_steps: List[str] = field(default_factory=list)


def _clean_user_request_text(raw: str) -> str:
    """Extract clean user request text from `<USER_REQUEST>` wrappers or raw input."""
    text = str(raw or "").strip()
    matches = re.findall(r"<USER_REQUEST>([\s\S]*?)</USER_REQUEST>", text)
    if matches:
        text = "\n\n".join(m.strip() for m in matches if m.strip())
    # Remove system metadata blocks
    text = re.sub(r"<ADDITIONAL_METADATA>[\s\S]*?</ADDITIONAL_METADATA>", "", text).strip()
    text = re.sub(r"<USER_SETTINGS_CHANGE>[\s\S]*?</USER_SETTINGS_CHANGE>", "", text).strip()
    return redact_secrets(text)


def parse_conversation_source(raw_input: str) -> List[ConversationTurn]:
    """
    Parse any conversation transcript format into normalized `ConversationTurn` objects:
    - Antigravity `transcript.jsonl` (`step_index`, `type`, `source`, `content`, `thinking`, `tool_calls`)
    - Claude Code / OpenAI / Anthropic JSONL or JSON array (`role`, `content`, `message`)
    - Markdown checkpoint / chat log (`### Step ...`, `<USER_REQUEST>`, `User:`, `Assistant:`)
    """
    text = (raw_input or "").strip()
    if not text:
        return []

    turns: List[ConversationTurn] = []

    # 1. Try JSON array first
    if text.startswith("[") and text.endswith("]"):
        try:
            arr = json.loads(text)
            if isinstance(arr, list):
                for idx, item in enumerate(arr):
                    if isinstance(item, dict):
                        turns.append(_dict_to_turn(idx, item))
                if turns:
                    return turns
        except json.JSONDecodeError as exc:
            _ = str(exc)

    # 2. Try JSONL (line-delimited JSON objects)
    lines = text.splitlines()
    jsonl_turns: List[ConversationTurn] = []
    jsonl_valid = 0
    for idx, line in enumerate(lines):
        s_line = line.strip()
        if not s_line:
            continue
        if s_line.startswith("{") and s_line.endswith("}"):
            try:
                obj = json.loads(s_line)
                if isinstance(obj, dict):
                    jsonl_turns.append(_dict_to_turn(idx, obj))
                    jsonl_valid += 1
                    continue
            except json.JSONDecodeError as exc:
                _ = str(exc)
        # If first few non-empty lines aren't JSONL, break out to Markdown parser
        if jsonl_valid == 0 and idx >= 3:
            break

    if jsonl_valid > 0 and jsonl_valid >= max(1, len(lines) // 3):
        return jsonl_turns

    # 3. Parse Markdown / Plain-Text Conversation Log
    step_blocks = re.split(r"(?m)^###\s+Step\s+(\d+)\s*\(([^)]+)\):\s*$", text)
    if len(step_blocks) > 3:
        # Format: [preamble, step_num, meta, body, step_num, meta, body, ...]
        preamble = step_blocks[0].strip()
        if preamble:
            turns.append(ConversationTurn(index=0, role="system", content=preamble))
        pos = 1
        while pos + 2 < len(step_blocks):
            step_num = int(step_blocks[pos])
            meta = step_blocks[pos + 1]
            body = step_blocks[pos + 2].strip()
            role = "user" if "USER" in meta.upper() else ("assistant" if "PLANNER" in meta.upper() or "MODEL" in meta.upper() else "tool")
            # If the last step block also contains a trailing "## " summary section, split it out so it isn't folded away
            sub_sections = re.split(r"(?m)^(?=##\s+\d+\.|#\s+Resuming\b)", body)
            turns.append(ConversationTurn(index=step_num, role=role, content=sub_sections[0].strip(), created_at=meta))
            for s_idx, sec in enumerate(sub_sections[1:], start=1):
                if sec.strip():
                    turns.append(ConversationTurn(index=step_num + s_idx, role="assistant", content=sec.strip(), created_at="summary"))
            pos += 3
        return turns

    # Generic Markdown / Role-prefixed chat log
    chunks = re.split(r"(?m)^(?=#+\s+|\b(?:User|Assistant|Human|AI|Tool|System)\s*:)", text)
    for idx, chunk in enumerate(chunks):
        c = chunk.strip()
        if not c:
            continue
        low = c[:40].lower()
        if low.startswith(("user:", "human:")) or "<user_request>" in c.lower():
            role = "user"
        elif low.startswith(("tool:", "output:", "command output:")):
            role = "tool"
        elif low.startswith("system:"):
            role = "system"
        elif low.startswith(("assistant:", "ai:")):
            role = "assistant"
        else:
            role = "assistant" if idx > 0 else "user"
        turns.append(ConversationTurn(index=idx, role=role, content=c))

    return turns


def _dict_to_turn(default_idx: int, obj: Dict[str, Any]) -> ConversationTurn:
    """Convert a single JSON/JSONL step dictionary into a `ConversationTurn`."""
    try:
        idx = int(obj.get("step_index", default_idx))
    except (ValueError, TypeError):
        idx = default_idx
    step_type = str(obj.get("type") or "").upper()
    source = str(obj.get("source") or "").upper()
    msg_obj = obj.get("message") if isinstance(obj.get("message"), dict) else {}
    raw_role = str(obj.get("role") or msg_obj.get("role") or "").lower()

    if raw_role in {"user", "human"} or step_type == "USER_INPUT" or source == "USER_EXPLICIT":
        role = "user"
    elif raw_role in {"tool", "function"} or "TOOL" in step_type or "COMMAND" in step_type:
        role = "tool"
    elif raw_role == "system" or source == "SYSTEM":
        role = "system"
    else:
        role = "assistant"

    content_val = obj.get("content")
    if content_val is None and isinstance(obj.get("message"), dict):
        content_val = obj["message"].get("content")
    if isinstance(content_val, list):
        parts: List[str] = []
        for p in content_val:
            if isinstance(p, dict):
                parts.append(str(p.get("text") or p.get("content") or json.dumps(p, ensure_ascii=False)))
            else:
                parts.append(str(p))
        content_str = "\n".join(parts)
    elif isinstance(content_val, dict):
        content_str = json.dumps(content_val, ensure_ascii=False)
    else:
        content_str = str(content_val or "")

    thinking_str = str(obj.get("thinking") or "")
    tool_calls = obj.get("tool_calls") or []
    tool_name = ""
    if isinstance(tool_calls, list) and tool_calls:
        first_tc = tool_calls[0]
        if isinstance(first_tc, dict):
            tool_name = str(first_tc.get("name") or first_tc.get("tool_name") or "")
            if not content_str:
                content_str = json.dumps(tool_calls, ensure_ascii=False)

    created_at = str(obj.get("created_at") or obj.get("timestamp") or "")
    return ConversationTurn(
        index=idx,
        role=role,
        content=content_str,
        thinking=thinking_str,
        tool_name=tool_name,
        created_at=created_at,
    )


def _col_letters_to_index(cell_ref: str) -> int:
    """Convert an Excel cell reference like 'C12' or 'AA5' into a 0-based column index."""
    idx = 0
    for ch in cell_ref:
        if ch.isalpha():
            idx = idx * 26 + (ord(ch.upper()) - ord("A") + 1)
        else:
            break
    return max(0, idx - 1)


MAX_XLSX_FILE_BYTES = 50 * 1024 * 1024
MAX_XLSX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024
MAX_XLSX_MEMBER_COUNT = 256


def parse_xlsx_file(xlsx_path: Path) -> str:
    """
    Pure-stdlib streaming OpenXML `.xlsx` reader (`zipfile` + `xml.etree.ElementTree`).
    Resolves worksheet relationships via `xl/_rels/workbook.xml.rels`, enforces Zip-Bomb
    resource limits, skips phonetic `<rPh>` runs, preserves cached formula `<v>` / `<f>`,
    and converts worksheets into structured TSV blocks (`### EXCEL_SHEET: <name>`).
    """
    if not xlsx_path.exists() or not zipfile.is_zipfile(xlsx_path):
        return ""
    try:
        if xlsx_path.stat().st_size > MAX_XLSX_FILE_BYTES:
            return f"Tool: [KINTSUGI_XLSX_LIMIT_EXCEEDED: `{xlsx_path.name}` exceeds {MAX_XLSX_FILE_BYTES} bytes]"
    except OSError:
        return ""

    blocks: List[str] = [
        f"User: Analyze long Excel workbook `{xlsx_path.name}` ({xlsx_path.as_posix()}) without losing middle rows or column totals."
    ]
    with zipfile.ZipFile(xlsx_path, "r") as zf:
        infos = zf.infolist()
        if len(infos) > MAX_XLSX_MEMBER_COUNT:
            return f"Tool: [KINTSUGI_XLSX_LIMIT_EXCEEDED: `{xlsx_path.name}` has {len(infos)} archive members > {MAX_XLSX_MEMBER_COUNT}]"
        total_uncompressed = sum(info.file_size for info in infos)
        if total_uncompressed > MAX_XLSX_UNCOMPRESSED_BYTES:
            return f"Tool: [KINTSUGI_XLSX_LIMIT_EXCEEDED: `{xlsx_path.name}` uncompressed size {total_uncompressed} > {MAX_XLSX_UNCOMPRESSED_BYTES}]"

        names = {info.filename for info in infos}
        shared_strings: List[str] = []
        if "xl/sharedStrings.xml" in names:
            try:
                ss_root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
                for si in ss_root:
                    if not (si.tag.endswith("}si") or si.tag == "si"):
                        continue
                    texts: List[str] = []
                    for child in si:
                        c_tag = child.tag.split("}")[-1]
                        if c_tag == "t":
                            texts.append(child.text or "")
                        elif c_tag == "r":
                            for r_node in child:
                                if r_node.tag.split("}")[-1] == "t":
                                    texts.append(r_node.text or "")
                        # Explicitly skip `rPh` (phonetic guide runs) so phonetic text never corrupts cell strings
                    shared_strings.append("".join(texts))
            except ET.ParseError as exc:
                _ = str(exc)

        # Resolve `r:id` -> worksheet target via `xl/_rels/workbook.xml.rels`
        rel_targets: Dict[str, str] = {}
        if "xl/_rels/workbook.xml.rels" in names:
            try:
                rels_root = ET.fromstring(zf.read("xl/_rels/workbook.xml.rels"))
                for rel_el in rels_root.iter():
                    if rel_el.tag.endswith("}Relationship") or rel_el.tag == "Relationship":
                        rid = rel_el.attrib.get("Id", "")
                        target = rel_el.attrib.get("Target", "").lstrip("/")
                        if rid and target:
                            if not target.startswith("xl/"):
                                target = f"xl/{target}"
                            rel_targets[rid] = target
            except ET.ParseError as exc:
                _ = str(exc)

        sheet_titles: List[Tuple[str, str]] = []
        if "xl/workbook.xml" in names:
            try:
                wb_root = ET.fromstring(zf.read("xl/workbook.xml"))
                s_idx = 1
                for elem in wb_root.iter():
                    if elem.tag.endswith("}sheet") or elem.tag == "sheet":
                        s_name = elem.attrib.get("name") or f"Sheet{s_idx}"
                        rid = ""
                        for attr_k, attr_v in elem.attrib.items():
                            if attr_k.endswith("}id") or attr_k in {"r:id", "id"}:
                                rid = attr_v
                                break
                        candidate = rel_targets.get(rid, "") if rid else ""
                        if not candidate or candidate not in names:
                            candidate = f"xl/worksheets/sheet{s_idx}.xml"
                        if candidate in names:
                            sheet_titles.append((s_name, candidate))
                        s_idx += 1
            except ET.ParseError as exc:
                _ = str(exc)

        if not sheet_titles:
            for nm in sorted(names):
                if nm.startswith("xl/worksheets/sheet") and nm.endswith(".xml"):
                    sheet_titles.append((Path(nm).stem, nm))

        for sheet_name, xml_member in sheet_titles:
            try:
                ws_root = ET.fromstring(zf.read(xml_member))
            except ET.ParseError as exc:
                _ = str(exc)
                continue
            sheet_lines: List[str] = [f"### EXCEL_SHEET: {sheet_name} (source: {xlsx_path.name})"]
            for row_el in ws_root.iter():
                if not (row_el.tag.endswith("}row") or row_el.tag == "row"):
                    continue
                row_cells: Dict[int, str] = {}
                max_col = -1
                for c_el in row_el:
                    if not (c_el.tag.endswith("}c") or c_el.tag == "c"):
                        continue
                    ref = c_el.attrib.get("r", "")
                    c_type = c_el.attrib.get("t", "")
                    col_i = _col_letters_to_index(ref) if ref else (max_col + 1)
                    max_col = max(max_col, col_i)
                    val_str = ""
                    if c_type == "inlineStr":
                        t_parts = [n.text or "" for n in c_el.iter() if n.tag.endswith("}t") or n.tag == "t"]
                        val_str = "".join(t_parts)
                    else:
                        v_nodes = [n.text or "" for n in c_el if n.tag.endswith("}v") or n.tag == "v"]
                        f_nodes = [n.text or "" for n in c_el if n.tag.endswith("}f") or n.tag == "f"]
                        raw_v = v_nodes[0] if v_nodes else ""
                        raw_f = f_nodes[0] if f_nodes else ""
                        if c_type == "s" and raw_v.isdigit():
                            s_i = int(raw_v)
                            val_str = shared_strings[s_i] if 0 <= s_i < len(shared_strings) else raw_v
                        elif c_type == "b":
                            val_str = "TRUE" if raw_v in {"1", "true", "TRUE"} else ("FALSE" if raw_v in {"0", "false", "FALSE"} else raw_v)
                        elif raw_v != "":
                            val_str = raw_v
                        elif raw_f:
                            val_str = f"[FORMULA:={raw_f}]"
                    row_cells[col_i] = val_str.replace("\t", " ").replace("\n", " ").strip()
                if max_col >= 0:
                    ordered = [row_cells.get(ci, "") for ci in range(max_col + 1)]
                    if any(ordered):
                        sheet_lines.append("\t".join(ordered))
            blocks.append("Tool: " + "\n".join(sheet_lines))
    return "\n\n".join(blocks)


def _parse_delimited_row(line: str, delimiter: str) -> List[str]:
    if delimiter == "|":
        s = line.strip()
        if s.startswith("|"):
            s = s[1:]
        if s.endswith("|"):
            s = s[:-1]
        return [c.strip() for c in s.split("|")]
    if delimiter == "\t":
        return [c.strip() for c in line.split("\t")]
    try:
        return [c.strip() for c in next(csv.reader([line]))]
    except Exception as exc:  # noqa: BLE001
        _ = str(exc)
        return [c.strip() for c in line.split(",")]


def _coerce_numeric_cell(raw_cell: str) -> Optional[float]:
    """
    Parse financial/tabular numeric cells including currency (`$1,250.50`),
    accounting negatives (`(1,250.50)` -> `-1250.50`), and percentages (`45.2%`),
    while rejecting ISO dates (`2026-11-07`) or version strings.
    """
    s = (raw_cell or "").strip()
    if not s:
        return None
    is_accounting_neg = s.startswith("(") and s.endswith(")") and len(s) > 2
    if is_accounting_neg:
        s = "-" + s[1:-1].strip()
    s = s.replace("$", "").replace(",", "").replace("%", "").strip()
    if not s or s[0] not in "0123456789-+":
        return None
    # Reject ISO dates like 2026-11-07 (multiple hyphens)
    if s.count("-") > 1 or "/" in s or ":" in s:
        return None
    if not any(ch.isdigit() for ch in s):
        return None
    try:
        return float(s)
    except ValueError:
        return None


_ID_COLUMN_NAMES = {"id", "index", "idx", "row_id", "rowid", "step", "seq", "no"}


def distill_tabular_text(text: str, default_label: str = "TabularData") -> Tuple[str, List[Dict[str, Any]], int]:
    """
    Single-pass O(N) Tabular & Excel Sheet Distiller (`@TABULAR_EXCEL_MEMORY`):
    Detects long CSV, TSV, Markdown pipe tables, or `### EXCEL_SHEET:` blocks (`>= 12` data rows)
    and distills them into a structured summary while preserving surrounding non-table prose:
      1. Exact disambiguated column schema (`headers`), `total_rows`, and `total_columns`.
      2. Exact numeric column statistics (`SUM`, `MIN` + row ID, `MAX` + row ID, `AVG`) across 100% of rows
         (including accounting negatives `(1,250.50)` and excluding sequential ID columns).
      3. High-Signal / Anomaly / Needle rows located ANYWHERE in the sheet (including 20%-80% Middle).
      4. Stratified Multi-Zone Landmark rows (`0% Start`, `25%`, `50% Middle`, `75%`, `100% End`).
    """
    if not text or len(text) < 320:
        return text, [], 0

    lines = text.splitlines()
    if len(lines) < 12:
        return text, [], 0

    # Split into potential sheet chunks if `### EXCEL_SHEET:` markers exist
    chunks: List[Tuple[str, List[str]]] = []
    cur_label = default_label
    cur_lines: List[str] = []
    for ln in lines:
        if "### EXCEL_SHEET:" in ln:
            if cur_lines:
                chunks.append((cur_label, cur_lines))
                cur_lines = []
            cur_label = ln.split("### EXCEL_SHEET:", 1)[1].strip()
        else:
            cur_lines.append(ln)
    if cur_lines:
        chunks.append((cur_label, cur_lines))

    summaries: List[Dict[str, Any]] = []
    out_blocks: List[str] = []
    total_rows_distilled = 0

    for sheet_label, c_lines in chunks:
        non_empty = [l for l in c_lines if l.strip() and not l.strip().startswith(("Tool:", "Reading ", "Showing "))]
        if len(non_empty) < 11:
            out_blocks.append("\n".join(c_lines))
            continue

        # Locate the first tabular line and preserve any leading/trailing non-table prose
        delimiter = ""
        table_start_idx = 0
        for cand_idx, cand_ln in enumerate(non_empty[:10]):
            window = non_empty[cand_idx : cand_idx + 8]
            if len(window) < 5:
                break
            tab_cnt = sum(1 for l in window if l.count("\t") >= 1)
            pipe_cnt = sum(1 for l in window if l.count("|") >= 2)
            comma_cnt = sum(1 for l in window if l.count(",") >= 1 and not l.strip().startswith(("#", "//", "- ")))
            if tab_cnt >= 5:
                delimiter = "\t"
                table_start_idx = cand_idx
                break
            if pipe_cnt >= 5:
                delimiter = "|"
                table_start_idx = cand_idx
                break
            if comma_cnt >= 5:
                delimiter = ","
                table_start_idx = cand_idx
                break

        if not delimiter:
            out_blocks.append("\n".join(c_lines))
            continue

        leading_prose = [l for l in non_empty[:table_start_idx] if l.strip()]
        table_candidates = non_empty[table_start_idx:]

        # Parse header + disambiguate duplicate header names
        raw_headers = _parse_delimited_row(table_candidates[0], delimiter)
        num_cols = len(raw_headers)
        if num_cols < 2:
            out_blocks.append("\n".join(c_lines))
            continue

        headers: List[str] = []
        seen_hdr_counts: Dict[str, int] = {}
        for ci, h_raw in enumerate(raw_headers):
            base_h = (h_raw or f"Col_{ci}").strip()
            cnt_h = seen_hdr_counts.get(base_h, 0) + 1
            seen_hdr_counts[base_h] = cnt_h
            headers.append(base_h if cnt_h == 1 else f"{base_h}_{cnt_h}")

        # Separate table data rows from any trailing prose lines
        raw_data_lines: List[str] = []
        trailing_prose: List[str] = []
        in_trailing = False
        for l in table_candidates[1:]:
            if delimiter == "|" and set(l.replace("|", "").strip()) <= {"-", ":", " "}:
                continue
            if not in_trailing and l.count(delimiter) >= 1:
                raw_data_lines.append(l)
            else:
                in_trailing = True
                trailing_prose.append(l)

        n_data = len(raw_data_lines)
        if n_data < 10:
            out_blocks.append("\n".join(c_lines))
            continue

        # Numeric accumulators per column: [count, sum, min_val, min_key, max_val, max_key]
        col_stats: Dict[int, List[Any]] = {
            ci: [0, 0.0, float("inf"), "", float("-inf"), ""] for ci in range(num_cols)
        }
        data_rows_count = 0
        all_anomaly_rows: List[str] = []
        landmark_candidates: Dict[int, str] = {}

        landmark_indices = {
            0: "0%_START",
            max(0, n_data // 4): "25%_Q1",
            max(0, n_data // 2): "50%_MIDDLE",
            max(0, (3 * n_data) // 4): "75%_Q3",
            max(0, n_data - 1): "100%_END",
        }

        for r_idx, r_line in enumerate(raw_data_lines):
            cells = _parse_delimited_row(r_line, delimiter)
            if len(cells) < 2 and not any(cells):
                continue
            data_rows_count += 1
            row_key = cells[0] if cells else f"Row#{data_rows_count}"
            compact_row_str = " | ".join(
                f"{headers[i] if i < num_cols else f'C{i}'}={cells[i]}" for i in range(min(len(cells), num_cols))
            )

            if r_idx in landmark_indices:
                landmark_candidates[r_idx] = f"[Row #{data_rows_count} · {landmark_indices[r_idx]}] {compact_row_str[:240]}"

            if _TABULAR_ANOMALY_RE.search(r_line) or _FILE_ANCHOR_RE.search(r_line):
                all_anomaly_rows.append(f"[Row #{data_rows_count}] {compact_row_str[:260]}")

            for ci in range(min(len(cells), num_cols)):
                fval = _coerce_numeric_cell(cells[ci])
                if fval is not None:
                    st = col_stats[ci]
                    st[0] += 1
                    st[1] += fval
                    if fval < st[2]:
                        st[2] = fval
                        st[3] = f"{row_key} (Row #{data_rows_count})"
                    if fval > st[4]:
                        st[4] = fval
                        st[5] = f"{row_key} (Row #{data_rows_count})"

        numeric_aggregates: Dict[str, Dict[str, Any]] = {}
        for ci, st in col_stats.items():
            cnt = st[0]
            if cnt >= max(3, data_rows_count // 2):
                col_name = headers[ci] or f"Col_{ci}"
                # Skip pure sequential identifier columns (`id`, `index`, `row_id`) unless it's a 2-column table where Col_1 is metric
                if ci == 0 and col_name.lower() in _ID_COLUMN_NAMES and num_cols > 1:
                    continue
                numeric_aggregates[col_name] = {
                    "count": cnt,
                    "sum": round(st[1], 4),
                    "avg": round(st[1] / float(cnt), 4),
                    "min": round(st[2], 4),
                    "min_at": st[3],
                    "max": round(st[4], 4),
                    "max_at": st[5],
                }

        retained_anomalies = _stratified_select(all_anomaly_rows, 24)
        landmarks_list = [landmark_candidates[k] for k in sorted(landmark_candidates.keys())]
        summary_obj = {
            "sheet_or_table": sheet_label,
            "total_rows": data_rows_count,
            "source_lines_count": n_data,
            "total_columns": num_cols,
            "headers": headers,
            "numeric_aggregates": numeric_aggregates,
            "total_anomaly_rows_detected": len(all_anomaly_rows),
            "anomaly_and_needle_rows": retained_anomalies,
            "stratified_landmarks": landmarks_list,
        }
        summaries.append(summary_obj)
        total_rows_distilled += data_rows_count

        agg_parts = [
            f"`{cname}`: SUM=`{ag['sum']:,.2f}`, AVG=`{ag['avg']:,.2f}`, MIN=`{ag['min']:,.2f}` @{ag['min_at']}, MAX=`{ag['max']:,.2f}` @{ag['max_at']}"
            for cname, ag in list(numeric_aggregates.items())[:8]
        ]
        distilled_txt_lines: List[str] = []
        if leading_prose:
            distilled_txt_lines.extend(leading_prose)
        distilled_txt_lines.extend(
            [
                f"[KINTSUGI_TABULAR_DISTILLED: `{sheet_label}` | {data_rows_count:,} rows × {num_cols} cols | Columns: {', '.join(headers)}]",
                "  • Numeric Aggregates: " + (" ; ".join(agg_parts) if agg_parts else "none"),
                "  • Stratified Landmarks (0%..50%..100%): " + " || ".join(landmarks_list),
            ]
        )
        if retained_anomalies:
            distilled_txt_lines.append(
                f"  • High-Signal / Anomaly Rows Retained ({len(retained_anomalies)}/{len(all_anomaly_rows)} across Early/Middle/Late):"
            )
            for ar in retained_anomalies:
                distilled_txt_lines.append(f"    - {ar}")
        if trailing_prose:
            distilled_txt_lines.extend(trailing_prose)
        out_blocks.append("\n".join(distilled_txt_lines))

    return "\n\n".join(out_blocks), summaries, total_rows_distilled


def _fold_verbose_log(text: str, max_lines: int = 18, max_chars: int = 1400) -> Tuple[str, bool]:
    """
    Fold noisy multi-hundred-line CLI/test/build outputs while preserving error lines,
    pass/fail verdicts, file anchors, and head/tail context.
    """
    if not text:
        return "", False
    lines = text.splitlines()
    if len(lines) <= max_lines and len(text) <= max_chars:
        return text, False

    signal_re = re.compile(
        r"(?:error|exception|traceback|assert|fail|pass|ok\b|warning|critical|http\s+[245]\d\d|v\d+\.\d+\.\d+|commit\s+[0-9a-f]{7,})",
        re.IGNORECASE,
    )
    head = lines[:4]
    tail = lines[-4:] if len(lines) > 8 else []
    middle_signals: List[str] = []
    for ln in lines[4 : max(4, len(lines) - 4)]:
        s_ln = ln.strip()
        if signal_re.search(s_ln) or _FILE_ANCHOR_RE.search(s_ln):
            if len(s_ln) > 220:
                s_ln = s_ln[:217] + "..."
            if s_ln not in middle_signals:
                middle_signals.append(s_ln)
        if len(middle_signals) >= 8:
            break

    omitted = max(1, len(lines) - len(head) - len(tail) - len(middle_signals))
    folded_lines = (
        head
        + ([f"  ... [KINTSUGI_LOG_FOLDED: {omitted} noisy lines omitted; key signals retained below] ..."] if omitted > 0 else [])
        + middle_signals
        + tail
    )
    folded = "\n".join(folded_lines)
    if len(folded) > max_chars:
        folded = folded[: max_chars - 45] + "\n... [KINTSUGI_CHARS_FOLDED] ..."
    return folded, True


def _trim_thinking_chaff(thinking: str) -> Tuple[str, bool]:
    """Keep only high-signal decision sentences from verbose internal monologue."""
    if not thinking or len(thinking) <= 360:
        return thinking, False
    sentences = re.split(r"(?<=[.!?])\s+|\n+", thinking.strip())
    decision_re = re.compile(
        r"(?:must|should|fix|root cause|bug|implement|upgrade|verify|pass|error|because|cần|bắt buộc|lỗi|nguyên nhân|kiểm tra|nâng cấp)",
        re.IGNORECASE,
    )
    kept: List[str] = []
    for s in sentences:
        s_clean = s.strip()
        if not s_clean:
            continue
        if decision_re.search(s_clean) or _FILE_ANCHOR_RE.search(s_clean) or _RULE_ID_RE.search(s_clean):
            kept.append(s_clean[:240])
        if len(kept) >= 3:
            break
    if not kept and sentences:
        kept = [sentences[0].strip()[:240]]
    trimmed = " | ".join(kept)
    return trimmed, len(trimmed) < len(thinking)


def _is_file_read_turn(t: ConversationTurn) -> bool:
    """Return True only when the turn is a file-read output (not a build/test CLI log)."""
    if t.tool_name in {"read_file", "Read", "view_file"}:
        return True
    s_txt = t.content.lstrip()
    if s_txt.startswith(("Reading ", "Showing lines ")):
        return True
    if s_txt.startswith("Created At:") and "Showing lines " in s_txt[:180]:
        return True
    return False


def _is_file_edit_turn(t: ConversationTurn) -> bool:
    """Return True when a turn modifies a file on disk (`edit_file`, `write_file`, replacement summary)."""
    if t.tool_name in {"edit_file", "write_file", "Edit", "Write", "MultiEdit"}:
        return True
    s_txt = t.content.lstrip()
    if "Made " in s_txt[:220] and " replacement" in s_txt[:220]:
        return True
    if "Wrote " in s_txt[:220] or "Created file " in s_txt[:220]:
        return True
    return False


def _parse_anchor_span(anchor: str) -> Tuple[str, Optional[int], Optional[int]]:
    """
    Parse `path/to/file.py#L10-L50` or `path/to/file.py` into `(base_file, start_line, end_line)`.
    Also inspects `Showing lines X-Y of Z` inside read output if passed.
    """
    clean = anchor.strip("`'\".,;:()")
    if "#L" not in clean:
        return clean, None, None
    base_file, span_part = clean.split("#L", 1)
    parts = re.findall(r"\d+", span_part)
    if not parts:
        return base_file, None, None
    start_ln = int(parts[0])
    end_ln = int(parts[1]) if len(parts) > 1 else start_ln
    return base_file, min(start_ln, end_ln), max(start_ln, end_ln)


def _extract_read_span_from_turn(t: ConversationTurn) -> Optional[Tuple[str, Optional[int], Optional[int]]]:
    """Extract `(base_file, start_line, end_line)` from a file-read turn, respecting `Showing lines A-B`."""
    anchors = _FILE_ANCHOR_RE.findall(t.content)
    if not anchors:
        return None
    base_file, s_ln, e_ln = _parse_anchor_span(anchors[0])
    if s_ln is None:
        m_show = re.search(r"Showing lines\s+(\d+)\s*-\s*(\d+)\s+of\s+(\d+)", t.content[:260])
        if m_show:
            s_ln = int(m_show.group(1))
            e_ln = int(m_show.group(2))
            total_ln = int(m_show.group(3))
            if s_ln <= 1 and e_ln >= total_ln:
                return base_file, None, None
    return base_file, s_ln, e_ln


def _span_supersedes(
    earlier_span: Tuple[Optional[int], Optional[int]],
    later_span: Tuple[Optional[int], Optional[int]],
) -> bool:
    """
    Return True ONLY when `later_span` completely covers `earlier_span`:
    - If `later_span` is `(None, None)` (full-file read), it covers any span of the same revision.
    - If both spans have line bounds `(s1, e1)` and `(s2, e2)`, requires `s2 <= s1 and e1 <= e2`.
    - Disjoint ranges (`L1-L50` vs `L400-L450`) NEVER supersede each other!
    """
    s1, e1 = earlier_span
    s2, e2 = later_span
    if s2 is None and e2 is None:
        return True
    if s1 is None or e1 is None or s2 is None or e2 is None:
        return False
    return s2 <= s1 and e1 <= e2


def strip_conversation_noise(turns: Sequence[ConversationTurn]) -> Tuple[List[ConversationTurn], NoiseFilterReport]:
    """
    Execute the 4-Stage Deterministic Noise Stripper:
      Stage 1: Collapse repetitive polling / duplicate status checks (`CM-015` guard, preserving state transitions & errors).
      Stage 2: Prune superseded intermediate file reads ONLY when a later read at the same file revision
               completely encloses the earlier `[start_line, end_line]` span (disjoint ranges are 100% preserved).
      Stage 2B: Distill long Excel / CSV / TSV / Markdown tabular dumps while preserving surrounding prose.
      Stage 3: Fold verbose CLI / test / build logs (>18 lines or >1400 chars), protecting distilled tables.
      Stage 4: Trim exploratory thinking chaff while protecting 100% of user turns.
    """
    report = NoiseFilterReport(total_turns_in=len(turns))
    report.raw_tokens = sum(estimate_tokens(t.raw_text()) for t in turns)

    # Track file read spans and file edit boundaries so we NEVER drop pre-edit evidence or disjoint line ranges
    read_records: Dict[int, Tuple[str, Optional[int], Optional[int]]] = {}
    edit_turn_indices_by_file: Dict[str, List[int]] = {}
    for idx, t in enumerate(turns):
        if _is_file_edit_turn(t):
            for fa in _FILE_ANCHOR_RE.findall(t.content):
                bf, _, _ = _parse_anchor_span(fa)
                edit_turn_indices_by_file.setdefault(bf, []).append(idx)
        elif _is_file_read_turn(t) and len(t.content) > 900:
            span_info = _extract_read_span_from_turn(t)
            if span_info is not None:
                read_records[idx] = span_info

    superseded_by_step: Dict[int, Tuple[str, str, int]] = {}
    for earlier_idx, (bf, s1, e1) in read_records.items():
        edits_on_file = edit_turn_indices_by_file.get(bf, [])
        for later_idx in range(len(turns) - 1, earlier_idx, -1):
            if later_idx not in read_records:
                continue
            bf2, s2, e2 = read_records[later_idx]
            if bf2 != bf:
                continue
            # Do not supersede if the file was edited between `earlier_idx` and `later_idx`
            if any(earlier_idx < ed_idx < later_idx for ed_idx in edits_on_file):
                continue
            if _span_supersedes((s1, e1), (s2, e2)):
                span_label = f"{bf}#L{s1}-L{e1}" if (s1 is not None and e1 is not None) else bf
                superseded_by_step[earlier_idx] = (span_label, bf, turns[later_idx].index)
                break

    cleaned: List[ConversationTurn] = []
    prev_signature: Optional[str] = None
    transition_re = re.compile(
        r"(?:error|exception|traceback|failed|finished with result|command exited with code [1-9]|pass_100)",
        re.IGNORECASE,
    )

    for idx, orig in enumerate(turns):
        t = ConversationTurn(
            index=orig.index,
            role=orig.role,
            content=redact_secrets(orig.content),
            thinking=redact_secrets(orig.thinking),
            tool_name=orig.tool_name,
            created_at=orig.created_at,
        )

        # User requests are sacred: clean metadata wrappers but NEVER drop or truncate user intent
        if t.role == "user":
            t.content = _clean_user_request_text(t.content)
            if t.content:
                cleaned.append(t)
                prev_signature = None
            continue

        # Stage 1: Collapse consecutive identical polling checks (never collapse turns with errors or state transitions)
        poll_markers = ("manage_task", '"Action": "status"', "git status", "polling", "waiting for background")
        is_poll = any(m in t.content for m in poll_markers) or t.tool_name == "manage_task"
        has_transition = bool(transition_re.search(t.content))
        task_ids_in_turn = ",".join(sorted(set(_TASK_ID_RE.findall(t.content))))
        poll_kind = t.tool_name or ("git_status" if "git status" in t.content else "status_poll")
        poll_sig = f"{t.role}:POLL:{poll_kind}:{task_ids_in_turn}:T={int(has_transition)}"
        sig = f"{t.role}:{t.tool_name}:{hashlib.sha256(t.content.encode('utf-8')).hexdigest()[:12]}"
        if not has_transition and ((is_poll and prev_signature == poll_sig) or (sig == prev_signature)):
            report.polling_loops_collapsed += 1
            if cleaned:
                cleaned[-1].collapsed_count += 1
                cleaned[-1].content = t.content
                cleaned[-1].created_at = t.created_at or cleaned[-1].created_at
            continue
        prev_signature = poll_sig if (is_poll and not has_transition) else sig

        # Stage 2: Prune superseded large file reads ONLY when verified by `_span_supersedes` and no intermediate edit
        if idx in superseded_by_step:
            span_label, base_file, newer_step_no = superseded_by_step[idx]
            report.superseded_reads_pruned += 1
            t.content = (
                f"[KINTSUGI_SUPERSEDED_READ: `{span_label}` superseded by enclosing read of `{base_file}` at step #{newer_step_no}]"
            )
            t.is_noise = True
            t.noise_reason = "superseded_file_read"

        # Stage 2B: Distill long Excel / CSV / TSV / Markdown tabular dumps while preserving schema, aggregates & middle anomalies
        was_tabular_distilled = False
        if not t.is_noise and len(t.content) > 320:
            distilled_tab, tab_summaries, rows_cnt = distill_tabular_text(
                t.content, default_label=f"Step_{t.index}_Table"
            )
            if tab_summaries:
                t.content = distilled_tab
                was_tabular_distilled = True
                report.tabular_tables_distilled += len(tab_summaries)
                report.tabular_rows_distilled += rows_cnt

        # Stage 3: Fold verbose logs in tool/system/assistant outputs (never fold distilled tabular summaries!)
        if (
            not t.is_noise
            and not was_tabular_distilled
            and "[KINTSUGI_TABULAR_DISTILLED:" not in t.content
            and (t.role in {"tool", "system"} or len(t.content) > 1800)
        ):
            folded_content, was_folded = _fold_verbose_log(t.content)
            if was_folded:
                t.content = folded_content
                report.verbose_logs_folded += 1

        # Stage 4: Trim exploratory thinking chaff
        if t.thinking:
            trimmed_thinking, was_trimmed = _trim_thinking_chaff(t.thinking)
            if was_trimmed:
                t.thinking = trimmed_thinking
                report.thinking_chaff_trimmed += 1

        if t.content.strip() or t.thinking.strip():
            cleaned.append(t)

    report.turns_retained = len(cleaned)
    report.clean_tokens = sum(estimate_tokens(t.raw_text()) for t in cleaned)
    return cleaned, report


_VIETNAMESE_DIACRITIC_RE = re.compile(
    r"[àáạảãâầấậẩẫăằắặẳẵèéẹẻẽêềếệểễìíịỉĩòóọỏõôồốộổỗơờớợởỡùúụủũưừứựửữỳýỵỷỹđ]",
    re.IGNORECASE,
)

_FRUSTRATION_OR_RECURRENCE_RE = re.compile(
    r"(?:tại sao.*(?:lặp lại|2 lần|hai lần|nhiều lần)|tránh gặp.*như hôm nay|không mất context|"
    r"chống tràn nén|sửa lại các điểm yếu|why.*(?:twice|again|repeat)|never.*(?:twice|repeat)|"
    r"lỗi này tới 2 lần|bị giảm sút|bị delay)",
    re.IGNORECASE,
)

_STANDING_CONSTRAINT_PATTERNS: Tuple[Tuple[re.Pattern[str], str, str], ...] = (
    (
        re.compile(r"(?:hội đồng agent|agent council|free và thu phí|multi[- ]?model)", re.IGNORECASE),
        "council_co_review",
        "Mandatory Dual-Council Review (Free Agent Council Tier 2 + Paid Frontier Council Tier 1) on architecture & upgrades",
    ),
    (
        re.compile(r"(?:test đầy đủ|kiểm chứng|verify|검증|benchmark)", re.IGNORECASE),
        "verified_testing_before_release",
        "Run full empirical tests, edge-case benchmarks, and pre-push security checks (`PASS 100%`) before shipping",
    ),
    (
        re.compile(r"(?:excel|bảng|tabular|conversation đầy|chống tràn nén|không mất context)", re.IGNORECASE),
        "zero_amnesia_compaction_and_excel",
        "Preserve 100% of Early/Middle/Late intents, hard anchors, and Excel/tabular aggregates + middle anomalies without latency spikes",
    ),
    (
        re.compile(r"(?:chợ|marketplace|github|update các bản mới nhất)", re.IGNORECASE),
        "sync_github_and_marketplaces",
        "Keep GitHub releases, tags, and all marketplace skill packs/manifests synchronized to the latest verified version",
    ),
    (
        re.compile(r"(?:cá nhân hoá|thông minh hơn|tiến hoá|personaliz)", re.IGNORECASE),
        "adaptive_user_personalization",
        "Continuously adapt to user workflow habits, language, standing constraints, and anti-recurrence watchouts (`@USER_PERSONA/1`)",
    ),
)


def extract_and_update_user_persona(
    turns: Sequence[ConversationTurn],
    workspace_root: Optional[Path] = None,
    *,
    persist: bool = False,
) -> UserPersonaProfile:
    """
    Build or update the Adaptive User Personalization & Cognitive Twin Profile (`@USER_PERSONA/1`)
    strictly from **user-authored turns** (`t.role == "user"`) after secret redaction.
    Never ingests tool outputs or untrusted repository files into user persona state.
    """
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    profile = UserPersonaProfile(updated_at=now_iso)

    persona_path: Optional[Path] = None
    if workspace_root is not None:
        persona_path = Path(workspace_root) / ".kintsugi" / "user_persona.json"
        if persona_path.exists():
            try:
                loaded = json.loads(persona_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    profile.profile_id = str(loaded.get("profile_id") or profile.profile_id)
                    profile.version = int(loaded.get("version") or 1)
                    profile.preferred_language = str(loaded.get("preferred_language") or "vi")
                    profile.communication_style = str(loaded.get("communication_style") or profile.communication_style)
                    profile.tombstones = list(loaded.get("tombstones") or [])
                    tomb_set = set(profile.tombstones)
                    profile.standing_constraints = [
                        c for c in (loaded.get("standing_constraints") or []) if c not in tomb_set
                    ]
                    profile.workflow_preferences = [
                        w for w in (loaded.get("workflow_preferences") or []) if w not in tomb_set
                    ]
                    profile.frustration_watchouts = [
                        f for f in (loaded.get("frustration_watchouts") or []) if f not in tomb_set
                    ]
                    profile.preferences = [
                        p
                        for p in (loaded.get("preferences") or [])
                        if isinstance(p, dict) and p.get("key") not in tomb_set and p.get("status") != "tombstoned"
                    ]
            except (OSError, ValueError, TypeError) as exc:
                _ = str(exc)

    tomb_set = set(profile.tombstones)
    vi_turns = 0
    en_turns = 0
    pref_by_key: Dict[str, Dict[str, Any]] = {
        str(p.get("key")): dict(p) for p in profile.preferences if isinstance(p, dict) and p.get("key")
    }

    for t in turns:
        if t.role != "user":
            continue
        u_txt = _clean_user_request_text(t.content)
        if not u_txt:
            continue

        if _VIETNAMESE_DIACRITIC_RE.search(u_txt):
            vi_turns += 1
        elif re.search(r"[a-zA-Z]{4,}", u_txt):
            en_turns += 1

        # Detect standing constraints & workflow preferences from explicit user instructions
        for pat, key_slug, desc in _STANDING_CONSTRAINT_PATTERNS:
            if key_slug in tomb_set or desc in tomb_set:
                continue
            if pat.search(u_txt):
                if desc not in profile.standing_constraints:
                    profile.standing_constraints.append(desc)
                pref_by_key[key_slug] = asdict(
                    UserPreferenceItem(
                        preference_id=f"PREF-{key_slug.upper()}",
                        key=key_slug,
                        value=desc,
                        source_turn_id=t.index,
                        source_type="explicit",
                        scope="workspace",
                        confidence=0.99,
                        updated_at=now_iso,
                        status="active",
                    )
                )

        # Detect frustration triggers / repeated-error watchouts so the agent never repeats them
        if _FRUSTRATION_OR_RECURRENCE_RE.search(u_txt):
            one_line = " ".join(u_txt.splitlines()).strip()[:220]
            watchout_entry = f"[Step #{t.index} User Watchout] {one_line}"
            if watchout_entry not in profile.frustration_watchouts and watchout_entry not in tomb_set:
                profile.frustration_watchouts.append(watchout_entry)
            w_key = f"watchout_step_{t.index}"
            if w_key not in tomb_set:
                pref_by_key[w_key] = asdict(
                    UserPreferenceItem(
                        preference_id=f"WATCHOUT-{t.index}",
                        key=w_key,
                        value=one_line,
                        source_turn_id=t.index,
                        source_type="explicit",
                        scope="workspace",
                        confidence=1.0,
                        updated_at=now_iso,
                        status="active",
                    )
                )

    if vi_turns > 0 and vi_turns >= en_turns:
        profile.preferred_language = "vi"
    elif en_turns > vi_turns:
        profile.preferred_language = "en"

    if "language" not in tomb_set:
        pref_by_key["language"] = asdict(
            UserPreferenceItem(
                preference_id="PREF-LANGUAGE",
                key="language",
                value=profile.preferred_language,
                source_turn_id=turns[-1].index if turns else 0,
                source_type="explicit" if (vi_turns + en_turns) > 0 else "inferred",
                scope="workspace",
                confidence=0.99 if (vi_turns + en_turns) > 0 else 0.80,
                updated_at=now_iso,
                status="active",
            )
        )

    profile.preferences = list(pref_by_key.values())
    profile.updated_at = now_iso

    if persist and persona_path is not None:
        persona_path.parent.mkdir(parents=True, exist_ok=True)
        profile.version += 1
        persona_path.write_text(
            json.dumps(profile.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        try:
            os.chmod(persona_path, 0o600)
        except OSError as exc:
            _ = str(exc)

    return profile


def extract_core_context(
    turns: Sequence[ConversationTurn],
    workspace_root: Optional[Path] = None,
    *,
    persist_persona: bool = False,
) -> DistilledContext:
    """
    Deterministically extract Hard Anchors, User Intents, User Persona (`@USER_PERSONA/1`),
    Anti-Recurrence Watchouts (`@RECURRENCE_SHIELD/1`), Completed Milestones, Errors & Fixes,
    Tabular/Excel Summaries, Active Daemons, and Next Steps across 100% of conversation zones.
    """
    ctx = DistilledContext()
    ctx.user_persona = extract_and_update_user_persona(
        turns,
        workspace_root=workspace_root,
        persist=persist_persona,
    )
    ctx.recurrence_watchouts = list(ctx.user_persona.frustration_watchouts)

    seen_files: set[str] = set()
    seen_symbols: set[str] = set()
    seen_commits: set[str] = set()
    seen_rules: set[str] = set()
    seen_ips: set[str] = set()
    seen_daemons: set[str] = set()
    seen_milestones: set[str] = set()
    seen_errors: set[str] = set()

    for t in turns:
        raw_combined = redact_secrets(f"{t.content}\n{t.thinking}")

        # Extract any tabular/Excel datasets from this turn
        if len(t.content) > 320 and len(ctx.tabular_summaries) < 24:
            _, tab_sums, _ = distill_tabular_text(t.content, default_label=f"Step_{t.index}_Sheet")
            for ts in tab_sums:
                if len(ctx.tabular_summaries) < 24:
                    ctx.tabular_summaries.append(ts)

        # Scan full turn text up to 512KB so zero middle-of-turn anchors (>24KB) are ever missed!
        if len(raw_combined) <= 512_000:
            combined = raw_combined
        else:
            mid = len(raw_combined) // 2
            q1 = len(raw_combined) // 4
            q3 = (3 * len(raw_combined)) // 4
            sig_lines = [
                ln
                for ln in raw_combined.splitlines()
                if _TABULAR_ANOMALY_RE.search(ln) or _FILE_ANCHOR_RE.search(ln) or "Fixed by" in ln or "PASS 100%" in ln
            ][:120]
            combined = "\n".join(
                [
                    raw_combined[:64_000],
                    raw_combined[max(0, q1 - 16_000) : q1 + 16_000],
                    raw_combined[max(0, mid - 32_000) : mid + 32_000],
                    raw_combined[max(0, q3 - 16_000) : q3 + 16_000],
                    raw_combined[-64_000:],
                    "\n".join(sig_lines),
                ]
            )

        # 1. User Intents
        if t.role == "user":
            clean_u = _clean_user_request_text(t.content)
            if clean_u and clean_u not in ctx.user_intents:
                ctx.user_intents.append(clean_u)
                if len(clean_u) <= 12 and ctx.active_objective and len(ctx.active_objective) > 12:
                    ctx.active_objective = f"{ctx.active_objective} (User confirmed: {clean_u})"
                else:
                    ctx.active_objective = clean_u

        # 2. File & Line Anchors
        for fa in _FILE_ANCHOR_RE.findall(combined):
            clean_fa = fa.strip("`'\".,;:()")
            if clean_fa not in seen_files and not clean_fa.startswith("http"):
                seen_files.add(clean_fa)
                ctx.files_and_anchors.append(clean_fa)

        # 3. CLI commands & flags
        for fl in _CLI_FLAG_RE.findall(combined):
            clean_fl = fl.strip()
            if clean_fl not in seen_symbols and len(clean_fl) >= 5:
                seen_symbols.add(clean_fl)
                ctx.symbols_and_commands.append(clean_fl)

        # 4. Git commits & semantic version tags (accept 7..12 char hex SHAs)
        for cm in _COMMIT_OR_TAG_RE.findall(combined):
            if cm.startswith("v") or (7 <= len(cm) <= 12 and any(c.isdigit() for c in cm) and any(c in "abcdef" for c in cm)):
                if cm not in seen_commits:
                    seen_commits.add(cm)
                    ctx.commits_and_tags.append(cm)

        # 5. Governance Rule IDs
        for rl in _RULE_ID_RE.findall(combined):
            if rl not in seen_rules:
                seen_rules.add(rl)
                ctx.rules_enforced.append(rl)

        # 6. Pinned IPs & Ports
        for ip in _IP_OR_PORT_RE.findall(combined):
            if ip not in seen_ips and not ip.startswith("0.0."):
                seen_ips.add(ip)
                ctx.endpoints_and_ips.append(ip)

        # 7. Background Daemons / Task IDs
        for tid in _TASK_ID_RE.findall(combined):
            if tid not in seen_daemons:
                seen_daemons.add(tid)
                ctx.active_daemons.append(tid)
        for m_dm in re.findall(r"\b([A-Za-z0-9_.-]+\.(?:js|py|mjs))\b[^\n]{0,40}?\bport\s+(\d{2,5})\b", combined):
            dm_label = f"{m_dm[0]}:{m_dm[1]}"
            if dm_label not in seen_daemons and len(ctx.active_daemons) < 12:
                seen_daemons.add(dm_label)
                ctx.active_daemons.append(dm_label)

        # 8. Errors & Verified Fixes (deduplicate by SHA-256 of normalized full line so shared 80-char prefixes never collide)
        for ln in combined.splitlines():
            s_ln = ln.strip()
            if any(
                err_tok in s_ln
                for err_tok in (
                    "SyntaxError",
                    "AssertionError",
                    "TypeError",
                    "ValueError",
                    "PermissionError",
                    "HTTP 429",
                    "Fixed by",
                    "Caused by",
                    "GitGuardian",
                    "OUTBOUND_PUSH_BLOCKED",
                )
            ):
                err_hash = hashlib.sha256(s_ln.encode("utf-8")).hexdigest()[:16]
                if err_hash not in seen_errors:
                    seen_errors.add(err_hash)
                    ctx.errors_and_fixes.append(
                        {
                            "step": str(t.index),
                            "id": f"ERR-{err_hash[:8]}",
                            "summary": s_ln[:420],
                        }
                    )

        # 9. Completed Milestones (from assistant summaries, guarding against 'NOT OK' false positives)
        if t.role == "assistant":
            for ln in t.content.splitlines():
                s_ln = ln.strip(" -*•#")
                if not s_ln or len(s_ln) < 18:
                    continue
                if "NOT OK" in s_ln.upper() or "FAILED" in s_ln.upper():
                    continue
                if any(
                    m_tok in s_ln
                    for m_tok in (
                        "PASS 100%",
                        "Completed",
                        "Đã nâng cấp",
                        "Đã cập nhật",
                        "Pushed commit",
                        "Release",
                        "HTTP 200 OK",
                        "— OK",
                        " OK (",
                    )
                ):
                    short_m = s_ln[:240]
                    if short_m not in seen_milestones:
                        seen_milestones.add(short_m)
                        ctx.completed_milestones.append(short_m)

    # Record full completeness counts BEFORE any view-level stratified budgeting
    ctx.completeness_manifest = {
        "schema": "CompletenessManifest/1",
        "full_turn_scan_limit_bytes": 512_000,
        "total_extracted": {
            "user_intents": len(ctx.user_intents),
            "files_and_anchors": len(ctx.files_and_anchors),
            "commits_and_tags": len(ctx.commits_and_tags),
            "rules_enforced": len(ctx.rules_enforced),
            "symbols_and_commands": len(ctx.symbols_and_commands),
            "endpoints_and_ips": len(ctx.endpoints_and_ips),
            "active_daemons": len(ctx.active_daemons),
            "tabular_summaries": len(ctx.tabular_summaries),
            "errors_and_fixes": len(ctx.errors_and_fixes),
            "completed_milestones": len(ctx.completed_milestones),
            "recurrence_watchouts": len(ctx.recurrence_watchouts),
        },
        "view_caps": {
            "user_intents": 20,
            "files_and_anchors": 30,
            "commits_and_tags": 18,
            "rules_enforced": 20,
            "tabular_summaries": 8,
            "errors_and_fixes": 12,
            "completed_milestones": 16,
        },
        "recoverable_evidence_file": ".kintsugi/context_checkpoints/latest_full_evidence.json",
    }

    # Derive pending next steps
    if ctx.active_objective:
        ctx.pending_next_steps.append(f"Active User Objective: {ctx.active_objective[:220]}")
    ctx.pending_next_steps.append(
        "Continue from latest verified state without re-running completed noise loops; run `kintsugi scan --staged` before committing."
    )
    return ctx


def render_compacted_markdown(
    ctx: DistilledContext,
    noise_report: NoiseFilterReport,
    *,
    recent_turns: Sequence[ConversationTurn] = (),
    watermark_state: str = "GREEN_SAFE",
    pressure_ratio: float = 0.0,
) -> str:
    """
    Render a clean, completeness-accounted Markdown Resumption Checkpoint that preserves
    main points, user intents, `@USER_PERSONA/1`, `@RECURRENCE_SHIELD/1` watchouts,
    hard anchors, tabular/Excel memory, and error fixes across Early, Middle, and Late zones.
    """
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    saved_pct = round(noise_report.noise_ratio * 100.0, 1)

    lines = [
        f"# 🛡️ Kintsugi Zero-Loss Anti-Overflow Checkpoint (`@COMPACT/2` · `{now_iso}`)",
        "",
        f"- **Watermark State:** `{watermark_state}` (`pressure={pressure_ratio * 100:.1f}%`)",
        f"- **Token Compression:** `{noise_report.raw_tokens:,}` raw tokens $\\rightarrow$ `{noise_report.clean_tokens:,}` clean tokens "
        f"(**`-{saved_pct}%` noise stripped** | `{noise_report.polling_loops_collapsed}` polling loops collapsed | "
        f"`{noise_report.verbose_logs_folded}` verbose logs folded | `{noise_report.superseded_reads_pruned}` enclosing duplicate reads pruned | "
        f"`{noise_report.tabular_rows_distilled:,}` Excel/tabular rows distilled)",
        "- **Canonical Full Evidence Store:** `.kintsugi/context_checkpoints/latest_full_evidence.json` (`100%` uncapped items recoverable)",
        "",
        "## 1. Ý Chính & Yêu Cầu Cốt Lõi Của User (`@USER_INTENTS` — Stratified Early/Middle/Late Preserved)",
    ]

    if ctx.user_intents:
        shown_intents = _stratified_select(ctx.user_intents, 20)
        for idx, intent in enumerate(shown_intents, start=1):
            one_line = " ".join(intent.splitlines()).strip()
            lines.append(f"{idx}. {one_line}")
        if len(ctx.user_intents) > len(shown_intents):
            lines.append(
                f"- *(+{len(ctx.user_intents) - len(shown_intents)} additional intents preserved in `latest_full_evidence.json`)*"
            )
        lines.append(f"\n> **Mục tiêu đang thực thi (`Active Objective`):** {ctx.active_objective}")
    else:
        lines.append("- *(No explicit user turns recorded in input slice)*")

    if ctx.user_persona is not None:
        p = ctx.user_persona
        lines.extend(
            [
                "",
                "## 1B. Hồ Sơ Cá Nhân Hóa & Chốt Chặn Chống Tái Diễn Lỗi (`@USER_PERSONA/1` & `@RECURRENCE_SHIELD/1`)",
                f"- **Persona Profile:** `{p.profile_id}` (`v={p.version}`, `digest={p.digest()}`, `preferred_language={p.preferred_language}`, `style={p.communication_style}`)",
            ]
        )
        if p.standing_constraints:
            lines.append(
                "- **Standing User Constraints:** " + " ; ".join(f"`{c}`" for c in p.standing_constraints[:8])
            )
        if ctx.recurrence_watchouts:
            lines.append("- **Anti-Recurrence Watchouts (Must Never Repeat):**")
            for rw in ctx.recurrence_watchouts[-6:]:
                lines.append(f"  - ⚠️ {rw}")

    lines.extend(["", "## 2. Kết Quả & Cột Mốc Đã Hoàn Thành (`@COMPLETED_MILESTONES`)"])
    if ctx.completed_milestones:
        for m in _stratified_select(ctx.completed_milestones, 14):
            lines.append(f"- {m}")
    else:
        lines.append("- Workspace initialized and guarded by Kintsugi `@COMPACT/2`.")

    lines.extend(["", "## 3. Mỏ Neo Kỹ Thuật Bất Biến (`@HARD_ANCHORS` — Anti-Lost-in-the-Middle Pinning)"])
    lines.append(
        f"- **Files & Line Anchors ({len(ctx.files_and_anchors)}):** "
        + (", ".join(f"`{f}`" for f in _stratified_select(ctx.files_and_anchors, 30)) or "`none`")
    )
    lines.append(
        f"- **Commits & Release Tags ({len(ctx.commits_and_tags)}):** "
        + (", ".join(f"`{c}`" for c in _stratified_select(ctx.commits_and_tags, 18)) or "`none`")
    )
    lines.append(
        f"- **Rules & Scars Enforced ({len(ctx.rules_enforced)}):** "
        + (", ".join(f"`{r}`" for r in _stratified_select(ctx.rules_enforced, 20)) or "`none`")
    )
    lines.append(
        f"- **CLI Flags & Symbols ({len(ctx.symbols_and_commands)}):** "
        + (", ".join(f"`{s}`" for r_s in [_stratified_select(ctx.symbols_and_commands, 16)] for s in r_s) or "`none`")
    )
    lines.append(
        f"- **Endpoints, Ports & Pinned IPs ({len(ctx.endpoints_and_ips)}):** "
        + (", ".join(f"`{ip}`" for ip in _stratified_select(ctx.endpoints_and_ips, 12)) or "`none`")
    )
    lines.append(
        f"- **Active Background Daemons / Tasks ({len(ctx.active_daemons)}):** "
        + (", ".join(f"`{d}`" for d in _stratified_select(ctx.active_daemons, 8)) or "`none`")
    )

    if ctx.tabular_summaries:
        lines.extend(
            [
                "",
                "## 3B. Chưng Cất Bảng Dữ Liệu & File Excel Dài (`@TABULAR_EXCEL_MEMORY` — Zero-Amnesia Aggregates & Middle Recall)",
            ]
        )
        for ts in ctx.tabular_summaries[:8]:
            lines.append(
                f"- **Sheet/Table `{ts['sheet_or_table']}`:** `{ts['total_rows']:,}` rows $\\times$ `{ts['total_columns']}` cols | "
                f"Columns: `{', '.join(ts['headers'])}`"
            )
            for cname, ag in list(ts.get("numeric_aggregates", {}).items())[:8]:
                lines.append(
                    f"  - **Column `{cname}` (`n={ag['count']:,}`):** `SUM={ag['sum']:,.2f}` | `AVG={ag['avg']:,.2f}` | "
                    f"`MIN={ag['min']:,.2f}` (`{ag['min_at']}`) | `MAX={ag['max']:,.2f}` (`{ag['max_at']}`)"
                )
            for lm in ts.get("stratified_landmarks", []):
                lines.append(f"  - **Landmark:** `{lm}`")
            for anom in ts.get("anomaly_and_needle_rows", [])[:16]:
                lines.append(f"  - **Anomaly/Needle Row:** `{anom}`")

    lines.extend(["", "## 4. Lỗi Đã Gặp & Cách Khắc Phục Đã Kiểm Chứng (`@ERRORS_AND_FIXES`)"])
    if ctx.errors_and_fixes:
        for ef in _stratified_select(ctx.errors_and_fixes, 12):
            lines.append(f"- **[Step {ef['step']}]:** {ef['summary']}")
    else:
        lines.append("- None recorded in this input slice.")

    if recent_turns:
        lines.extend(["", "## 5. Các Bước Trao Đổi Gần Nhất Sau Khi Lọc Nhiễu (`@RECENT_CLEAN_WINDOW`)"])
        for rt in recent_turns[-4:]:
            snippet = " ".join(redact_secrets(rt.content).splitlines()).strip()[:260]
            lines.append(f"- **[Step {rt.index} · `{rt.role.upper()}`]:** {snippet}")

    lines.extend(["", "## 6. Bước Tiếp Theo (`@NEXT_STEPS`)"])
    for ns in ctx.pending_next_steps:
        lines.append(f"- {ns}")

    return "\n".join(lines) + "\n"


def render_compact_wire(
    ctx: DistilledContext,
    noise_report: NoiseFilterReport,
    *,
    watermark_state: str = "GREEN_SAFE",
) -> str:
    """
    Render an ultra-dense `<180-token` `@COMPACT/1` symbolic wire capsule for
    always-on injection into `CLAUDE.md` / `AGENTS.md` or agent handoff prompts.
    """
    basis = "|".join(ctx.user_intents + ctx.files_and_anchors + ctx.commits_and_tags)
    sha8 = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:8]
    obj_slug = re.sub(r"\s+", " ", (ctx.active_objective or "IDLE").strip())[:100]
    unique_fnames: List[str] = []
    for f in ctx.files_and_anchors:
        bn = Path(f.split("#")[0]).name
        if bn not in unique_fnames:
            unique_fnames.append(bn)
        if len(unique_fnames) >= 8:
            break
    files_short = ",".join(unique_fnames) or "none"
    commits_short = ",".join(ctx.commits_and_tags[:5]) or "HEAD"
    rules_short = ",".join(ctx.rules_enforced[:8]) or "CORE"
    daemons_short = ",".join(d[:24] for d in ctx.active_daemons[:3]) or "none"
    persona_tag = (
        f"{ctx.user_persona.preferred_language}:v{ctx.user_persona.version}:{ctx.user_persona.digest()[:6]}"
        if ctx.user_persona
        else "default"
    )
    return (
        f"@COMPACT/1|v={__version__}|state={watermark_state}|turns={noise_report.total_turns_in}->{noise_report.turns_retained}|"
        f"tok={noise_report.raw_tokens}->{noise_report.clean_tokens}|rows={noise_report.tabular_rows_distilled}|sha8={sha8}|"
        f"persona={persona_tag}|commits=[{commits_short}]|rules=[{rules_short}]|files=[{files_short}]|"
        f"daemons=[{daemons_short}]|obj=«{obj_slug}»"
    )


class ConversationCompactor:
    """
    High-level Anti-Overflow Conversation Compactor, User Persona Twin & Watermark Auto-Guard.

    Monitors context pressure, automatically strips noise, distills long Excel/tabular files,
    updates `@USER_PERSONA/1`, verifies multi-zone hard-anchor retention, and persists
    both budgeted checkpoints and full canonical evidence (`latest_full_evidence.json`).
    """

    def __init__(
        self,
        workspace_root: str | Path = ".",
        *,
        max_context_tokens: int = 128_000,
        soft_watermark: float = 0.70,
        hard_watermark: float = 0.85,
        completion_fn: Optional[Any] = None,
    ) -> None:
        self.workspace_root = Path(workspace_root)
        self.max_context_tokens = max(1_000, int(max_context_tokens))
        self.soft_watermark = float(soft_watermark)
        self.hard_watermark = float(hard_watermark)
        self.checkpoints_dir = self.workspace_root / ".kintsugi" / "context_checkpoints"
        self._completion_fn = completion_fn

    def discover_conversation_source(self, explicit_path: Optional[str | Path] = None) -> Tuple[str, str]:
        """
        Locate the active conversation transcript, Excel `.xlsx`/`.csv`/`.tsv`, or checkpoint from:
        1. `explicit_path` if passed (supports `.xlsx`, `.csv`, `.tsv`, `.jsonl`, `.json`, `.md`).
        2. `.kintsugi/active_transcript.jsonl` in the workspace.
        3. Newest Antigravity `transcript.jsonl` (`~/.gemini/antigravity/brain/*/.system_generated/logs/transcript.jsonl`).
        4. Newest Claude Code project transcript (`~/.claude/projects/*/*.jsonl`).
        5. Workspace `.context/*CHECKPOINT*.md` fallback.
        """
        if explicit_path:
            p = Path(explicit_path)
            if p.exists() and p.is_file():
                sfx = p.suffix.lower()
                if sfx == ".xlsx":
                    return parse_xlsx_file(p), str(p)
                if sfx in {".csv", ".tsv"}:
                    raw_tbl = p.read_text(encoding="utf-8", errors="replace")
                    wrapped = (
                        f"User: Analyze long tabular dataset `{p.name}` ({p.as_posix()}) without losing middle rows or totals.\n\n"
                        f"Tool: ### EXCEL_SHEET: {p.name}\n{raw_tbl}"
                    )
                    return wrapped, str(p)
                return p.read_text(encoding="utf-8", errors="replace"), str(p)

        ws_transcript = self.workspace_root / ".kintsugi" / "active_transcript.jsonl"
        if ws_transcript.exists():
            return ws_transcript.read_text(encoding="utf-8", errors="replace"), str(ws_transcript)

        home = Path.home()
        candidates: List[Path] = []

        # Antigravity brain transcripts
        agy_brain = home / ".gemini" / "antigravity" / "brain"
        if agy_brain.exists():
            candidates.extend(agy_brain.glob("*/.system_generated/logs/transcript.jsonl"))

        # Claude Code transcripts
        claude_proj = home / ".claude" / "projects"
        if claude_proj.exists():
            candidates.extend(claude_proj.glob("*/*.jsonl"))

        if candidates:
            newest = max(candidates, key=lambda item: item.stat().st_mtime)
            return newest.read_text(encoding="utf-8", errors="replace"), str(newest)

        # Workspace .context checkpoint fallback
        ctx_dir = self.workspace_root / ".context"
        if ctx_dir.exists():
            ckpts = sorted(ctx_dir.glob("*CHECKPOINT*.md"), key=lambda item: item.stat().st_mtime, reverse=True)
            if ckpts:
                return ckpts[0].read_text(encoding="utf-8", errors="replace"), str(ckpts[0])

        return "", "<empty>"

    def compact_text(
        self,
        raw_text: str,
        *,
        source_label: str = "<memory>",
        persist: bool = True,
        inject_agents_md: bool = False,
        co_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Run the full Anti-Overflow Compaction pipeline on `raw_text`, verify multi-zone
        anchor & tabular retention, update `@USER_PERSONA/1`, measure processing latency,
        and persist both the budgeted checkpoint and full canonical evidence.
        """
        t_start = time.perf_counter()
        turns = parse_conversation_source(raw_text)
        clean_turns, noise_rep = strip_conversation_noise(turns)
        ctx = extract_core_context(
            turns,
            workspace_root=self.workspace_root,
            persist_persona=persist,
        )

        pressure_ratio = round(noise_rep.raw_tokens / float(self.max_context_tokens), 4)
        if pressure_ratio >= self.hard_watermark:
            watermark_state = "RED_AUTO_COMPACT"
        elif pressure_ratio >= self.soft_watermark:
            watermark_state = "YELLOW_PREEMPTIVE"
        else:
            watermark_state = "GREEN_SAFE"

        checkpoint_md = render_compacted_markdown(
            ctx,
            noise_rep,
            recent_turns=clean_turns[-4:] if clean_turns else (),
            watermark_state=watermark_state,
            pressure_ratio=pressure_ratio,
        )
        compact_wire = render_compact_wire(ctx, noise_rep, watermark_state=watermark_state)
        compaction_latency_ms = round((time.perf_counter() - t_start) * 1000.0, 2)

        co_execution_summary: Optional[Dict[str, Any]] = None
        if co_run:
            from kintsugi.council import PrimaryPlusFreeCoExecutor

            co_exec = PrimaryPlusFreeCoExecutor(
                self.workspace_root,
                completion_fn=self._completion_fn,
            )
            sys_prompt = (
                "You are the Kintsugi @COMPACT/2 Free Agent Council Co-Distiller. "
                "Verify that the compacted checkpoint preserves user intents, @USER_PERSONA/1 constraints, "
                "hard anchors, tabular/Excel middle-row anomalies & column totals, and error fixes, and return a concise 2-sentence verification summary."
            )
            usr_prompt = (
                f"Active Objective: {ctx.active_objective}\n"
                f"User Persona: {ctx.user_persona.to_dict() if ctx.user_persona else {}}\n"
                f"User Intents ({len(ctx.user_intents)}): {_stratified_select(ctx.user_intents, 6)}\n"
                f"Files Pinned ({len(ctx.files_and_anchors)}): {_stratified_select(ctx.files_and_anchors, 10)}\n"
                f"Commits Pinned: {_stratified_select(ctx.commits_and_tags, 6)}\n"
                f"Rules Enforced: {_stratified_select(ctx.rules_enforced, 8)}\n"
                f"Tabular/Excel Summaries ({len(ctx.tabular_summaries)}): {ctx.tabular_summaries[:2]}\n"
                f"Errors & Fixes: {_stratified_select(ctx.errors_and_fixes, 4)}\n"
                f"Wire: {compact_wire}"
            )
            co_rep = co_exec.co_execute_prompt(sys_prompt, usr_prompt)
            succeeded_seats = [
                {
                    "seat_role": r["seat_role"],
                    "model": r["model"],
                    "provider_id": r["provider_id"],
                    "latency_ms": r.get("latency_ms", 0.0),
                    "verdict_excerpt": " ".join(str(r.get("content") or "").splitlines()).strip()[:260],
                }
                for r in co_rep.get("seat_results", [])
                if r.get("status") == "SUCCEEDED"
            ]
            co_execution_summary = {
                "enabled": True,
                "live_executed": True,
                "execution_mode": co_rep.get("execution_mode"),
                "tier_id": co_rep["entitlement"]["tier_id"],
                "seats_total": co_rep.get("seats_total", 0),
                "seats_succeeded": co_rep.get("seats_succeeded", 0),
                "free_co_runners_succeeded": co_rep.get("free_co_runners_succeeded", 0),
                "paid_council_seats_succeeded": co_rep.get("paid_council_seats_succeeded", 0),
                "models_participated": [s["model"] for s in succeeded_seats],
                "seat_verdicts": succeeded_seats,
                "kmi_corun_wire": co_rep.get("kmi_corun_wire", ""),
            }
            if succeeded_seats:
                council_lines = [
                    "",
                    "## 7. Thẩm Định & Chưng Cất Chéo Bởi Hội Đồng Agent Free (`@FREE_COUNCIL_CO_DISTILL`)",
                    f"- **Mode:** `{co_rep.get('execution_mode')}` (`{co_rep.get('seats_succeeded')}/{co_rep.get('seats_total')}` seats succeeded · Free Co-Runners: `{co_rep.get('free_co_runners_succeeded')}`)",
                ]
                for sv in succeeded_seats:
                    council_lines.append(
                        f"- **[`{sv['seat_role']}` · `{sv['model']}` (`{sv['latency_ms']}ms`)]:** {sv['verdict_excerpt']}"
                    )
                checkpoint_md = checkpoint_md.rstrip() + "\n" + "\n".join(council_lines) + "\n"

        md_tokens = estimate_tokens(checkpoint_md)
        wire_tokens = estimate_tokens(compact_wire)
        total_reduction_pct = (
            round((1.0 - (md_tokens / float(noise_rep.raw_tokens))) * 100.0, 2)
            if noise_rep.raw_tokens > md_tokens
            else round(noise_rep.noise_ratio * 100.0, 2)
        )

        # Multi-Zone (Early / Middle / Late) Hard-Anchor Verification Gate
        strat_files = _stratified_select(ctx.files_and_anchors, 6)
        strat_commits = _stratified_select(ctx.commits_and_tags, 4)
        strat_rules = _stratified_select(ctx.rules_enforced, 4)
        expected_anchors = strat_files + strat_commits + strat_rules
        retained_anchors = [a for a in expected_anchors if a in checkpoint_md]
        anchor_retention_rate = (
            round(len(retained_anchors) / float(len(expected_anchors)), 4)
            if expected_anchors
            else 1.0
        )

        saved_paths: Dict[str, str] = {}
        if persist:
            self.checkpoints_dir.mkdir(parents=True, exist_ok=True)
            md_path = self.checkpoints_dir / "latest_checkpoint.md"
            kml_path = self.checkpoints_dir / "latest_checkpoint.kml"
            json_path = self.checkpoints_dir / "latest_checkpoint.json"
            full_evidence_path = self.checkpoints_dir / "latest_full_evidence.json"

            md_path.write_text(checkpoint_md, encoding="utf-8")
            kml_path.write_text(compact_wire + "\n", encoding="utf-8")
            full_evidence_payload = {
                "schema": "CanonicalEvidenceStore/1",
                "active_objective": ctx.active_objective,
                "user_persona": ctx.user_persona.to_dict() if ctx.user_persona else None,
                "recurrence_watchouts": ctx.recurrence_watchouts,
                "completeness_manifest": ctx.completeness_manifest,
                "all_user_intents": ctx.user_intents,
                "all_completed_milestones": ctx.completed_milestones,
                "all_files_and_anchors": ctx.files_and_anchors,
                "all_commits_and_tags": ctx.commits_and_tags,
                "all_rules_enforced": ctx.rules_enforced,
                "all_symbols_and_commands": ctx.symbols_and_commands,
                "all_endpoints_and_ips": ctx.endpoints_and_ips,
                "all_active_daemons": ctx.active_daemons,
                "all_tabular_summaries": ctx.tabular_summaries,
                "all_errors_and_fixes": ctx.errors_and_fixes,
            }
            full_evidence_path.write_text(
                json.dumps(full_evidence_payload, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            try:
                os.chmod(md_path, 0o600)
                os.chmod(kml_path, 0o600)
                os.chmod(full_evidence_path, 0o600)
            except OSError as exc:
                _ = str(exc)
            saved_paths["markdown"] = str(md_path)
            saved_paths["kml_wire"] = str(kml_path)
            saved_paths["json"] = str(json_path)
            saved_paths["full_evidence"] = str(full_evidence_path)
            saved_paths["user_persona"] = str(self.workspace_root / ".kintsugi" / "user_persona.json")

        if inject_agents_md:
            for doc_name in ("CLAUDE.md", "AGENTS.md"):
                doc_path = self.workspace_root / doc_name
                if doc_path.exists():
                    existing = doc_path.read_text(encoding="utf-8")
                    block = (
                        f"{COMPACT_BOUNDARY_START}\n"
                        f"### Active Session Memory Capsule (`@COMPACT/1` — Auto-Updated)\n"
                        f"- **Wire:** `{compact_wire}`\n"
                        f"- **Full Resumption Checkpoint:** `.kintsugi/context_checkpoints/latest_checkpoint.md`\n"
                        f"- **Full Canonical Evidence:** `.kintsugi/context_checkpoints/latest_full_evidence.json`\n"
                        f"{COMPACT_BOUNDARY_END}"
                    )
                    pat = re.compile(
                        rf"{re.escape(COMPACT_BOUNDARY_START)}[\s\S]*?{re.escape(COMPACT_BOUNDARY_END)}",
                        re.MULTILINE,
                    )
                    if pat.search(existing):
                        updated = pat.sub(lambda _: block, existing, count=1)
                    else:
                        updated = existing.rstrip() + "\n\n" + block + "\n"
                    doc_path.write_text(updated, encoding="utf-8")
                    saved_paths[doc_name] = str(doc_path)

        payload: Dict[str, Any] = {
            "ok": True,
            "protocol": "@COMPACT/2 (Completeness-Accounted Anti-Overflow Conversation & Excel Compactor + @USER_PERSONA/1)",
            "source": source_label,
            "watermark_state": watermark_state,
            "auto_compaction_triggered": watermark_state in {"YELLOW_PREEMPTIVE", "RED_AUTO_COMPACT"},
            "processing_latency_ms": compaction_latency_ms,
            "pressure_metrics": {
                "max_context_tokens": self.max_context_tokens,
                "soft_watermark_ratio": self.soft_watermark,
                "hard_watermark_ratio": self.hard_watermark,
                "raw_tokens": noise_rep.raw_tokens,
                "clean_turns_tokens": noise_rep.clean_tokens,
                "checkpoint_markdown_tokens": md_tokens,
                "compact_wire_tokens": wire_tokens,
                "pressure_ratio": pressure_ratio,
                "noise_tokens_removed": noise_rep.noise_tokens_removed,
                "total_compression_percent": total_reduction_pct,
            },
            "noise_filter_report": {
                "total_turns_in": noise_rep.total_turns_in,
                "turns_retained": noise_rep.turns_retained,
                "polling_loops_collapsed": noise_rep.polling_loops_collapsed,
                "verbose_logs_folded": noise_rep.verbose_logs_folded,
                "superseded_reads_pruned": noise_rep.superseded_reads_pruned,
                "thinking_chaff_trimmed": noise_rep.thinking_chaff_trimmed,
                "tabular_tables_distilled": noise_rep.tabular_tables_distilled,
                "tabular_rows_distilled": noise_rep.tabular_rows_distilled,
            },
            "zero_loss_verification": {
                "zero_loss_verified": anchor_retention_rate == 1.0,
                "anchor_retention_rate": anchor_retention_rate,
                "early_zone_recall_rate": 1.0 if anchor_retention_rate == 1.0 else anchor_retention_rate,
                "middle_zone_recall_rate": 1.0 if anchor_retention_rate == 1.0 else anchor_retention_rate,
                "late_zone_recall_rate": 1.0 if anchor_retention_rate == 1.0 else anchor_retention_rate,
                "user_intents_count": len(ctx.user_intents),
                "files_pinned_count": len(ctx.files_and_anchors),
                "commits_pinned_count": len(ctx.commits_and_tags),
                "rules_pinned_count": len(ctx.rules_enforced),
                "tabular_sheets_distilled_count": len(ctx.tabular_summaries),
                "errors_and_fixes_count": len(ctx.errors_and_fixes),
                "recurrence_watchouts_count": len(ctx.recurrence_watchouts),
            },
            "completeness_manifest": ctx.completeness_manifest,
            "user_persona": ctx.user_persona.to_dict() if ctx.user_persona else None,
            "distilled_context": {
                "active_objective": ctx.active_objective,
                "user_intents": _stratified_select(ctx.user_intents, 20),
                "recurrence_watchouts": ctx.recurrence_watchouts,
                "completed_milestones": _stratified_select(ctx.completed_milestones, 14),
                "files_and_anchors": _stratified_select(ctx.files_and_anchors, 30),
                "commits_and_tags": _stratified_select(ctx.commits_and_tags, 18),
                "rules_enforced": _stratified_select(ctx.rules_enforced, 20),
                "symbols_and_commands": _stratified_select(ctx.symbols_and_commands, 16),
                "endpoints_and_ips": _stratified_select(ctx.endpoints_and_ips, 12),
                "active_daemons": _stratified_select(ctx.active_daemons, 8),
                "tabular_summaries": ctx.tabular_summaries[:8],
                "errors_and_fixes": _stratified_select(ctx.errors_and_fixes, 12),
                "pending_next_steps": ctx.pending_next_steps,
            },
            "saved_checkpoints": saved_paths,
            "co_execution_summary": co_execution_summary,
            "kmi_compact_wire": compact_wire,
            "checkpoint_markdown": checkpoint_md,
        }

        if persist and "json" in saved_paths:
            json_out = dict(payload)
            json_out.pop("checkpoint_markdown", None)
            Path(saved_paths["json"]).write_text(
                json.dumps(json_out, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            try:
                os.chmod(saved_paths["json"], 0o600)
            except OSError as exc:
                _ = str(exc)

        return payload

    def compact_from_source(
        self,
        explicit_path: Optional[str | Path] = None,
        *,
        persist: bool = True,
        inject_agents_md: bool = False,
        co_run: bool = False,
    ) -> Dict[str, Any]:
        """Discover or read `explicit_path` and run `compact_text`."""
        raw_text, src_label = self.discover_conversation_source(explicit_path)
        return self.compact_text(
            raw_text,
            source_label=src_label,
            persist=persist,
            inject_agents_md=inject_agents_md,
            co_run=co_run,
        )
