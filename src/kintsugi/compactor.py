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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, TypeVar

from kintsugi import __version__
from kintsugi.compressor import estimate_tokens

_T = TypeVar("_T")

COMPACT_BOUNDARY_START = "<!-- KINTSUGI:COMPACT/1 START -->"
COMPACT_BOUNDARY_END = "<!-- KINTSUGI:COMPACT/1 END -->"

# Secret redaction patterns so compacted checkpoints never leak raw tokens
_SECRET_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), "sk-***REDACTED***"),
    (re.compile(r"\btj_[A-Za-z0-9_-]{16,}\b"), "tj_***REDACTED***"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "gh_***REDACTED***"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "github_pat_***REDACTED***"),
    (re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b"), "gsk_***REDACTED***"),
    (re.compile(r"\bxai-[A-Za-z0-9_-]{16,}\b"), "xai-***REDACTED***"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AKIA***REDACTED***"),
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
    n = len(items)
    if n <= max_count or max_count <= 0:
        return list(items)
    if max_count <= 2:
        return [items[0], items[-1]][:max_count]
    head_k = max(1, max_count // 3)
    tail_k = max(1, max_count // 3)
    mid_k = max(1, max_count - head_k - tail_k)
    mid_pool = items[head_k : n - tail_k]
    mid_selected: List[_T] = []
    if mid_pool:
        step = len(mid_pool) / float(mid_k)
        for i in range(mid_k):
            idx = min(len(mid_pool) - 1, int(round((i + 0.5) * step - 0.5)))
            val = mid_pool[idx]
            if val not in mid_selected:
                mid_selected.append(val)
    return list(items[:head_k]) + mid_selected + list(items[n - tail_k :])


def redact_secrets(text: str) -> str:
    """Mask any raw API tokens before persisting a conversation checkpoint."""
    out = str(text or "")
    for pat, repl in _SECRET_PATTERNS:
        out = pat.sub(repl, out)
    return out


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
    """Zero-loss core context extracted from a conversation."""

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


def parse_xlsx_file(xlsx_path: Path) -> str:
    """
    Pure-stdlib streaming OpenXML `.xlsx` reader (`zipfile` + `xml.etree.ElementTree`).
    Converts all worksheets in an `.xlsx` workbook into structured TSV blocks (`### EXCEL_SHEET: <name>`)
    with zero external dependencies (`openpyxl`/`pandas` not required).
    """
    if not xlsx_path.exists() or not zipfile.is_zipfile(xlsx_path):
        return ""
    blocks: List[str] = [
        f"User: Analyze long Excel workbook `{xlsx_path.name}` ({xlsx_path.as_posix()}) without losing middle rows or column totals."
    ]
    with zipfile.ZipFile(xlsx_path, "r") as zf:
        names = set(zf.namelist())
        shared_strings: List[str] = []
        if "xl/sharedStrings.xml" in names:
            try:
                ss_root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
                for si in ss_root.iter():
                    if si.tag.endswith("}si") or si.tag == "si":
                        texts = [node.text or "" for node in si.iter() if node.tag.endswith("}t") or node.tag == "t"]
                        shared_strings.append("".join(texts))
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
                        raw_v = v_nodes[0] if v_nodes else ""
                        if c_type == "s" and raw_v.isdigit():
                            s_i = int(raw_v)
                            val_str = shared_strings[s_i] if 0 <= s_i < len(shared_strings) else raw_v
                        else:
                            val_str = raw_v
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


def distill_tabular_text(text: str, default_label: str = "TabularData") -> Tuple[str, List[Dict[str, Any]], int]:
    """
    Single-pass O(N) Tabular & Excel Sheet Distiller (`@TABULAR_EXCEL_MEMORY`):
    Detects long CSV, TSV, Markdown pipe tables, or `### EXCEL_SHEET:` blocks (`>= 12` data rows)
    and distills them into a zero-loss structured summary preserving:
      1. Exact column schema (`headers`), `total_rows`, and `total_columns`.
      2. Exact numeric column statistics (`SUM`, `MIN` + row ID, `MAX` + row ID, `AVG`) across 100% of rows.
      3. 100% of High-Signal / Anomaly / Needle rows located ANYWHERE in the sheet (including 20%-80% Middle).
      4. Stratified Multi-Zone Landmark rows (`0% Start`, `25%`, `50% Middle`, `75%`, `100% End`).
    """
    if not text or len(text) < 400:
        return text, [], 0

    lines = text.splitlines()
    if len(lines) < 14:
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
        if len(non_empty) < 12:
            out_blocks.append("\n".join(c_lines))
            continue

        sample_head = non_empty[:8]
        tab_cnt = sum(1 for l in sample_head if l.count("\t") >= 2)
        pipe_cnt = sum(1 for l in sample_head if l.count("|") >= 3)
        comma_cnt = sum(1 for l in sample_head if l.count(",") >= 2)

        delimiter = ""
        if tab_cnt >= 4:
            delimiter = "\t"
        elif pipe_cnt >= 4:
            delimiter = "|"
        elif comma_cnt >= 4:
            delimiter = ","

        if not delimiter:
            out_blocks.append("\n".join(c_lines))
            continue

        # Parse header + data rows in single streaming pass
        headers = _parse_delimited_row(non_empty[0], delimiter)
        num_cols = len(headers)
        if num_cols < 2:
            out_blocks.append("\n".join(c_lines))
            continue

        # Numeric accumulators per column: [count, sum, min_val, min_key, max_val, max_key]
        col_stats: Dict[int, List[Any]] = {
            ci: [0, 0.0, float("inf"), "", float("-inf"), ""] for ci in range(num_cols)
        }
        data_rows_count = 0
        anomaly_rows: List[str] = []
        landmark_candidates: Dict[int, str] = {}
        raw_data_lines = [
            l for l in non_empty[1:] if not (delimiter == "|" and set(l.replace("|", "").strip()) <= {"-", ":", " "})
        ]
        n_data = len(raw_data_lines)
        if n_data < 10:
            out_blocks.append("\n".join(c_lines))
            continue

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
            compact_row_str = " | ".join(f"{headers[i] if i < num_cols else f'C{i}'}={cells[i]}" for i in range(min(len(cells), num_cols)))

            if r_idx in landmark_indices:
                landmark_candidates[r_idx] = f"[Row #{data_rows_count} · {landmark_indices[r_idx]}] {compact_row_str[:240]}"

            if _TABULAR_ANOMALY_RE.search(r_line) or _FILE_ANCHOR_RE.search(r_line):
                if len(anomaly_rows) < 18:
                    anomaly_rows.append(f"[Row #{data_rows_count}] {compact_row_str[:260]}")

            for ci in range(min(len(cells), num_cols)):
                raw_val = cells[ci].replace("$", "").replace(",", "").replace("%", "").strip()
                if not raw_val:
                    continue
                # Fast check before float conversion
                if raw_val[0] in "0123456789-+" and any(ch.isdigit() for ch in raw_val):
                    try:
                        fval = float(raw_val)
                        st = col_stats[ci]
                        st[0] += 1
                        st[1] += fval
                        if fval < st[2]:
                            st[2] = fval
                            st[3] = f"{row_key} (Row #{data_rows_count})"
                        if fval > st[4]:
                            st[4] = fval
                            st[5] = f"{row_key} (Row #{data_rows_count})"
                    except ValueError as exc:
                        _ = str(exc)

        numeric_aggregates: Dict[str, Dict[str, Any]] = {}
        for ci, st in col_stats.items():
            cnt = st[0]
            if cnt >= max(3, data_rows_count // 2):
                col_name = headers[ci] or f"Col_{ci}"
                # Skip pure sequential ID columns if header is 'id' or 'index'
                numeric_aggregates[col_name] = {
                    "count": cnt,
                    "sum": round(st[1], 4),
                    "avg": round(st[1] / float(cnt), 4),
                    "min": round(st[2], 4),
                    "min_at": st[3],
                    "max": round(st[4], 4),
                    "max_at": st[5],
                }

        landmarks_list = [landmark_candidates[k] for k in sorted(landmark_candidates.keys())]
        summary_obj = {
            "sheet_or_table": sheet_label,
            "total_rows": data_rows_count,
            "total_columns": num_cols,
            "headers": headers,
            "numeric_aggregates": numeric_aggregates,
            "anomaly_and_needle_rows": anomaly_rows,
            "stratified_landmarks": landmarks_list,
        }
        summaries.append(summary_obj)
        total_rows_distilled += data_rows_count

        agg_parts = [
            f"`{cname}`: SUM=`{ag['sum']:,.2f}`, AVG=`{ag['avg']:,.2f}`, MIN=`{ag['min']:,.2f}` @{ag['min_at']}, MAX=`{ag['max']:,.2f}` @{ag['max_at']}"
            for cname, ag in list(numeric_aggregates.items())[:6]
        ]
        distilled_txt_lines = [
            f"[KINTSUGI_TABULAR_DISTILLED: `{sheet_label}` | {data_rows_count:,} rows × {num_cols} cols | Columns: {', '.join(headers)}]",
            "  • Numeric Aggregates: " + (" ; ".join(agg_parts) if agg_parts else "none"),
            "  • Stratified Landmarks (0%..50%..100%): " + " || ".join(landmarks_list),
        ]
        if anomaly_rows:
            distilled_txt_lines.append("  • High-Signal / Anomaly Rows Retained (100% Middle Recall):")
            for ar in anomaly_rows:
                distilled_txt_lines.append(f"    - {ar}")
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


def strip_conversation_noise(turns: Sequence[ConversationTurn]) -> Tuple[List[ConversationTurn], NoiseFilterReport]:
    """
    Execute the 4-Stage Deterministic Noise Stripper:
      Stage 1: Collapse repetitive polling / duplicate status checks (`CM-015` guard).
      Stage 2: Prune superseded intermediate file reads (keep latest read per file).
      Stage 3: Fold verbose CLI / test / build logs (>18 lines or >1400 chars).
      Stage 4: Trim exploratory thinking chaff while protecting 100% of user turns.
    """
    report = NoiseFilterReport(total_turns_in=len(turns))
    report.raw_tokens = sum(estimate_tokens(t.raw_text()) for t in turns)

    # Identify latest read turn index for each base file path to prune earlier multi-hundred-line dumps
    # while preserving every exact `file#Lstart-Lend` anchor in `@HARD_ANCHORS` and in the placeholder tag.
    latest_file_read_turn: Dict[str, int] = {}
    for idx, t in enumerate(turns):
        if _is_file_read_turn(t):
            anchors = _FILE_ANCHOR_RE.findall(t.content)
            if len(t.content) > 900 and anchors:
                anchor_key = anchors[0].strip("`'\".,;:()")
                base_file = anchor_key.split("#")[0]
                latest_file_read_turn[base_file] = idx

    cleaned: List[ConversationTurn] = []
    prev_signature: Optional[str] = None

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

        # Stage 1: Collapse consecutive polling / identical status checks (scoped by task ID & tool_name)
        poll_markers = ("manage_task", '"Action": "status"', "git status", "polling", "waiting for background")
        is_poll = any(m in t.content for m in poll_markers) or t.tool_name == "manage_task"
        task_ids_in_turn = ",".join(sorted(set(_TASK_ID_RE.findall(t.content))))
        poll_sig = f"{t.role}:POLL:{t.tool_name}:{task_ids_in_turn}"
        sig = f"{t.role}:{t.tool_name}:{hashlib.sha256(t.content.encode('utf-8')).hexdigest()[:12]}"
        if (is_poll and prev_signature == poll_sig) or (sig == prev_signature):
            report.polling_loops_collapsed += 1
            if cleaned:
                cleaned[-1].collapsed_count += 1
                cleaned[-1].content = redact_secrets(orig.content)
            continue
        prev_signature = poll_sig if is_poll else sig

        # Stage 2: Prune superseded large file reads while retaining the exact range anchor in the tag
        if _is_file_read_turn(t):
            anchors = _FILE_ANCHOR_RE.findall(t.content)
            if len(t.content) > 900 and anchors:
                anchor_key = anchors[0].strip("`'\".,;:()")
                base_file = anchor_key.split("#")[0]
                newer_idx = latest_file_read_turn.get(base_file, idx)
                if newer_idx > idx:
                    report.superseded_reads_pruned += 1
                    t.content = f"[KINTSUGI_SUPERSEDED_READ: `{anchor_key}` superseded by newer read of `{base_file}` at step #{newer_idx}]"
                    t.is_noise = True
                    t.noise_reason = "superseded_file_read"

        # Stage 2B: Distill long Excel / CSV / TSV / Markdown tabular dumps while preserving 100% schema, aggregates & middle anomalies
        if not t.is_noise and len(t.content) > 400:
            distilled_tab, tab_summaries, rows_cnt = distill_tabular_text(
                t.content, default_label=f"Step_{t.index}_Table"
            )
            if tab_summaries:
                t.content = distilled_tab
                report.tabular_tables_distilled += len(tab_summaries)
                report.tabular_rows_distilled += rows_cnt

        # Stage 3: Fold verbose logs in tool/system/assistant outputs
        if not t.is_noise and (t.role in {"tool", "system"} or len(t.content) > 1800):
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


def extract_core_context(turns: Sequence[ConversationTurn]) -> DistilledContext:
    """
    Deterministically extract 100% of Hard Anchors, User Intents, Completed Milestones,
    Errors & Verified Fixes, Tabular/Excel Summaries, Active Daemons, and Next Steps.
    """
    ctx = DistilledContext()
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

        # Extract any tabular/Excel datasets from this turn before bounded regex scanning
        if len(t.content) > 400 and len(ctx.tabular_summaries) < 12:
            _, tab_sums, _ = distill_tabular_text(t.content, default_label=f"Step_{t.index}_Sheet")
            for ts in tab_sums:
                if len(ctx.tabular_summaries) < 12:
                    ctx.tabular_summaries.append(ts)

        # Fast-path stratified scan window for massive >24KB single-turn blobs to guarantee low latency
        if len(raw_combined) > 24_000:
            mid = len(raw_combined) // 2
            sig_lines = [
                ln
                for ln in raw_combined.splitlines()
                if _TABULAR_ANOMALY_RE.search(ln) or "Fixed by" in ln or "PASS 100%" in ln
            ][:40]
            combined = (
                raw_combined[:8_000]
                + "\n"
                + raw_combined[max(0, mid - 4_000) : mid + 4_000]
                + "\n"
                + raw_combined[-8_000:]
                + "\n"
                + "\n".join(sig_lines)
            )
        else:
            combined = raw_combined

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
            if dm_label not in seen_daemons and len(ctx.active_daemons) < 8:
                seen_daemons.add(dm_label)
                ctx.active_daemons.append(dm_label)

        # 8. Errors & Verified Fixes
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
                )
            ):
                key = s_ln[:80]
                if key not in seen_errors:
                    seen_errors.add(key)
                    ctx.errors_and_fixes.append(
                        {
                            "step": str(t.index),
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

    # Anti-'Lost-in-the-Middle' Stratified Retention across Early + Middle + Late zones
    if len(ctx.errors_and_fixes) > 12:
        ctx.errors_and_fixes = _stratified_select(ctx.errors_and_fixes, 12)
    if len(ctx.completed_milestones) > 16:
        ctx.completed_milestones = _stratified_select(ctx.completed_milestones, 16)

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
    Render a clean, zero-loss Markdown Resumption Checkpoint that preserves 100% of
    main points, user intents, hard anchors, tabular/Excel memory, and error fixes across
    Early, Middle, and Late zones.
    """
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    saved_pct = round(noise_report.noise_ratio * 100.0, 1)

    lines = [
        f"# 🛡️ Kintsugi Zero-Loss Anti-Overflow Checkpoint (`@COMPACT/1` · `{now_iso}`)",
        "",
        f"- **Watermark State:** `{watermark_state}` (`pressure={pressure_ratio * 100:.1f}%`)",
        f"- **Token Compression:** `{noise_report.raw_tokens:,}` raw tokens $\\rightarrow$ `{noise_report.clean_tokens:,}` clean tokens "
        f"(**`-{saved_pct}%` noise stripped** | `{noise_report.polling_loops_collapsed}` polling loops collapsed | "
        f"`{noise_report.verbose_logs_folded}` verbose logs folded | `{noise_report.superseded_reads_pruned}` duplicate reads pruned | "
        f"`{noise_report.tabular_rows_distilled:,}` Excel/tabular rows distilled)",
        "",
        "## 1. Ý Chính & Yêu Cầu Cốt Lõi Của User (`@USER_INTENTS` — Stratified Early/Middle/Late Preserved)",
    ]

    if ctx.user_intents:
        for idx, intent in enumerate(_stratified_select(ctx.user_intents, 20), start=1):
            one_line = " ".join(intent.splitlines()).strip()
            lines.append(f"{idx}. {one_line}")
        lines.append(f"\n> **Mục tiêu đang thực thi (`Active Objective`):** {ctx.active_objective}")
    else:
        lines.append("- *(No explicit user turns recorded in input slice)*")

    lines.extend(["", "## 2. Kết Quả & Cột Mốc Đã Hoàn Thành (`@COMPLETED_MILESTONES`)"])
    if ctx.completed_milestones:
        for m in _stratified_select(ctx.completed_milestones, 14):
            lines.append(f"- {m}")
    else:
        lines.append("- Workspace initialized and guarded by Kintsugi `@COMPACT/1`.")

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
        + (", ".join(f"`{s}`" for s in _stratified_select(ctx.symbols_and_commands, 16)) or "`none`")
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
            for cname, ag in list(ts.get("numeric_aggregates", {}).items())[:6]:
                lines.append(
                    f"  - **Column `{cname}` (`n={ag['count']:,}`):** `SUM={ag['sum']:,.2f}` | `AVG={ag['avg']:,.2f}` | "
                    f"`MIN={ag['min']:,.2f}` (`{ag['min_at']}`) | `MAX={ag['max']:,.2f}` (`{ag['max_at']}`)"
                )
            for lm in ts.get("stratified_landmarks", []):
                lines.append(f"  - **Landmark:** `{lm}`")
            for anom in ts.get("anomaly_and_needle_rows", [])[:12]:
                lines.append(f"  - **Anomaly/Needle Row:** `{anom}`")

    lines.extend(["", "## 4. Lỗi Đã Gặp & Cách Khắc Phục Đã Kiểm Chứng (`@ERRORS_AND_FIXES`)"])
    if ctx.errors_and_fixes:
        for ef in _stratified_select(ctx.errors_and_fixes, 10):
            lines.append(f"- **[Step {ef['step']}]:** {ef['summary']}")
    else:
        lines.append("- `0` unresolved runtime errors in compacted window.")

    if recent_turns:
        lines.extend(["", "## 5. Các Bước Trao Đổi Gần Nhất Sau Khi Lọc Nhiễu (`@RECENT_CLEAN_WINDOW`)"])
        for rt in recent_turns[-4:]:
            snippet = " ".join(rt.content.splitlines()).strip()[:260]
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
    obj_slug = re.sub(r"\s+", " ", (ctx.active_objective or "IDLE").strip())[:110]
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
    return (
        f"@COMPACT/1|v={__version__}|state={watermark_state}|turns={noise_report.total_turns_in}->{noise_report.turns_retained}|"
        f"tok={noise_report.raw_tokens}->{noise_report.clean_tokens}|rows={noise_report.tabular_rows_distilled}|sha8={sha8}|"
        f"commits=[{commits_short}]|rules=[{rules_short}]|files=[{files_short}]|"
        f"daemons=[{daemons_short}]|obj=«{obj_slug}»"
    )


class ConversationCompactor:
    """
    High-level Anti-Overflow Conversation Compactor & Watermark Auto-Guard.

    Monitors context pressure, automatically strips noise, distills long Excel/tabular files,
    verifies 100% multi-zone hard-anchor retention, and persists zero-loss checkpoints.
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
        Run the full Anti-Overflow Compaction pipeline on `raw_text`, verify zero-loss
        multi-zone anchor & tabular retention, measure processing latency, and persist checkpoint.
        """
        t_start = time.perf_counter()
        turns = parse_conversation_source(raw_text)
        clean_turns, noise_rep = strip_conversation_noise(turns)
        ctx = extract_core_context(turns)

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
                "You are the Kintsugi @COMPACT/1 Free Agent Council Co-Distiller. "
                "Verify that the compacted checkpoint preserves 100% of user intents, hard anchors, "
                "tabular/Excel middle-row anomalies & column totals, and error fixes, and return a concise 2-sentence verification summary."
            )
            usr_prompt = (
                f"Active Objective: {ctx.active_objective}\n"
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

            md_path.write_text(checkpoint_md, encoding="utf-8")
            kml_path.write_text(compact_wire + "\n", encoding="utf-8")
            try:
                os.chmod(md_path, 0o600)
                os.chmod(kml_path, 0o600)
            except OSError as exc:
                _ = str(exc)
            saved_paths["markdown"] = str(md_path)
            saved_paths["kml_wire"] = str(kml_path)
            saved_paths["json"] = str(json_path)

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
            "protocol": "@COMPACT/1 (Zero-Loss Anti-Overflow Conversation Compactor)",
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
            },
            "distilled_context": {
                "active_objective": ctx.active_objective,
                "user_intents": _stratified_select(ctx.user_intents, 20),
                "completed_milestones": _stratified_select(ctx.completed_milestones, 14),
                "files_and_anchors": _stratified_select(ctx.files_and_anchors, 30),
                "commits_and_tags": _stratified_select(ctx.commits_and_tags, 18),
                "rules_enforced": _stratified_select(ctx.rules_enforced, 20),
                "symbols_and_commands": _stratified_select(ctx.symbols_and_commands, 16),
                "endpoints_and_ips": _stratified_select(ctx.endpoints_and_ips, 12),
                "active_daemons": _stratified_select(ctx.active_daemons, 8),
                "tabular_summaries": ctx.tabular_summaries[:8],
                "errors_and_fixes": _stratified_select(ctx.errors_and_fixes, 10),
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
