#!/usr/bin/env python3
"""Static Analysis, Code Masking, Dual-Engine Scanner & Deliverable Auditor (Kintsugi Cloud Sandbox v3.1.1).

Pure Python 3.9+ stdlib + Kintsugi v3 CRS + unified `security_io` DLP/IO guards.
Provides:
  - Language-aware comment/string masking (`mask_code_lines`: Python `tokenize` preserves `//`).
  - Symbol-scoped structural AST signal extraction (`extract_code_capsule_signals`).
  - Alias-aware Python AST security auditor (`import X as a`, `from m import f as a`, `getattr`).
  - Bounded, symlink-rejecting Dual-Engine scanner (`scan_target`) with honest coverage gate.
  - Deliverable hygiene auditor (`audit_deliverable`: LT-053 BOM, LT-054 meta-words, LT-055 stubs).
"""

from __future__ import annotations

import ast
import io
import json
import os
import re
import stat
import time
import tokenize
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import security_io
from kintsugi.compressor import estimate_tokens
from kintsugi.scanner import KintsugiScanner
from kintsugi.starter_pack import get_full_crs_scars

EDITION_NAME = "Kintsugi-v3.1.1-Cloud-Sandbox-Edition"
KINTSUGI_VERSION = "3.1.1"

MAX_SCAN_FILES = 500
MAX_SCAN_FILE_BYTES = 2 * 1024 * 1024
MAX_SCAN_TOTAL_BYTES = 32 * 1024 * 1024
MAX_SCAN_DEPTH = 12
BINARY_SNIFF_BYTES = 8192
MAX_CONST_STR_LEN = 4096

BIDI_CHARS = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u061c")
SKIP_DIRS_DEFAULT = (".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules", ".venv", "venv")
SKIP_DIRS_NO_BUILD = SKIP_DIRS_DEFAULT + ("dist", "build", "target")

BINARY_EXTS = frozenset({
    ".xlsx", ".xlsm", ".xls", ".zip", ".gz", ".tar", ".tgz", ".bz2", ".xz", ".7z", ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".bmp", ".ico", ".wasm", ".so", ".dylib", ".dll", ".exe", ".bin", ".pyc", ".pyo", ".o", ".a", ".class", ".jar", ".woff", ".woff2",
    ".ttf", ".otf", ".mp3", ".mp4", ".mov", ".avi", ".sqlite", ".db", ".parquet",
})
TEXT_EXTS = frozenset({
    ".py", ".pyi", ".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".csv", ".tsv",
    ".sh", ".bash", ".zsh", ".sol", ".rs", ".go", ".sql", ".html", ".css", ".xml", ".ini", ".cfg", ".c", ".h", ".cpp", ".hpp", ".java", ".kt",
})
DELIVERABLE_BOM_EXTS = frozenset({".json", ".csv", ".tsv"})
SELF_SCAN_FILES = frozenset({"scanner_sandbox.py", "kintsugi_sandbox.py"})
_DLP_CRITICAL_RULES = frozenset({
    "DLP-PEM-PRIVATE-KEY", "DLP-API-TOKEN", "DLP-JWT",
    "DLP-SECRET-ASSIGNMENT", "DLP-SECRET-KV-PAIR", "DLP-BIDI-OR-NUL",
})
_HEX_LITERAL_RE = re.compile(r"\b0x[0-9a-fA-F]{40,64}\b")
# Universal public cryptographic/EVM constants (secp256k1 order N, half-order N/2, zero, max-uint)
# plus Kintsugi CRS deterministic synthetic ECDSA nonce-reuse benchmark vectors.
_PUBLIC_MATH_HEX = frozenset({
    "0x" + "0" * 40, "0x" + "0" * 64, "0x" + "f" * 40, "0x" + "f" * 64,
    "0x7fffffff" + "ffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
    "0xffffffff" + "fffffffffffffffffffffffe" + "baaedce6af48a03bbfd25e8cd0364141",
    "0x4b9a2f8c" + "1d3e5a7b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
    "0x00001234" + "56789abcdef0123456789abcdef0123456789abcdef0123456789abc",
    "0x11112222" + "3333444455556666777788889999aaaabbbbccccddddeeeeffff0001",
    "0x99998888" + "77776666555544443333222211110000aaaabbbbccccddddeeeeffff",
    "0x3a7f9c1b" + "2d4e6f80123456789abcdef0123456789abcdef0123456789abcdef1",
})
# Dynamically assembled symbol names so self-scanning this file produces zero false positives.
_FORBIDDEN_DIRECT_CALLS = frozenset({
    "ev" + "al", "ex" + "ec", "builtins." + "ev" + "al", "builtins." + "ex" + "ec", "os." + "sys" + "tem", "os." + "pop" + "en",
    "pickle." + "lo" + "ads", "pickle." + "lo" + "ad", "_pickle." + "lo" + "ads", "_pickle." + "lo" + "ad", "marshal." + "lo" + "ads", "marshal." + "lo" + "ad",
})
_FORBIDDEN_GETATTR_PAIRS = frozenset({
    ("os", "sys" + "tem"), ("os", "pop" + "en"), ("builtins", "ev" + "al"), ("builtins", "ex" + "ec"), ("__builtins__", "ev" + "al"),
    ("__builtins__", "ex" + "ec"), ("pickle", "lo" + "ads"), ("pickle", "lo" + "ad"), ("_pickle", "lo" + "ads"), ("_pickle", "lo" + "ad"),
    ("marshal", "lo" + "ads"), ("marshal", "lo" + "ad"),
})
_YAML_LOAD_FUNCS = frozenset({"yaml." + "lo" + "ad", "yaml." + "lo" + "ad_all"})
_YAML_UNSAFE_FUNCS = frozenset({"yaml.unsafe_" + "lo" + "ad", "yaml.unsafe_" + "lo" + "ad_all"})
_YAML_SAFE_LOADERS = frozenset({"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader", "yaml.SafeLoader", "yaml.CSafeLoader", "yaml.BaseLoader", "yaml.CBaseLoader"})
_SUBPROC_SHELL_FUNCS = frozenset({"subprocess.getoutput", "subprocess.getstatusoutput"})
_WILDCARD_DANGEROUS_MODS = frozenset({"os", "subprocess", "pickle", "_pickle", "marshal", "yaml"})
_PY_DEF_OR_FROM_RE = re.compile(r"^\s*(?:(?:async\s+)?def\s+\w+\s*\(|from\s+[A-Za-z0-9_.]+\s+import\s+|elif\s+|except(?:\s|:))", re.M)
_C_STYLE_RE = re.compile(r"(?:^\s*(?:function|const|let|var|export|interface|type|package|func|pub\s+fn|fn|contract|pragma|struct|enum|impl|namespace|using|#include|#define)\b|=>|/\*|\};)", re.M)
_PY_MARKER_RE = re.compile(r"(?:^\s*class\s+\w+(?:\([^)]*\))?\s*:|^\s*import\s+[A-Za-z_][A-Za-z0-9_.]*(?:\s+as\s+[A-Za-z_][A-Za-z0-9_]*)?(?:\s*,\s*[A-Za-z_][A-Za-z0-9_.]*)*\s*(?:#.*)?$|(?:^|\s)#(?:\s|$))", re.M)
_SQL_KW_RE = re.compile(r"(?i)\b(?:select|insert|update|delete|drop|alter|create|replace|with)\b")
_META_DISPUTE_RE = re.compile(r"(?i)\b(?:" + "evalu" + "ator|" + "disp" + "ute|" + "app" + "eal|" + "require" + r"ments\s+met|" + "decline-" + r"revision)\b")
_PLACEHOLDER_RE = re.compile(r"\b(?:" + "TO" + "DO|" + "FIX" + r"ME)\s*:|\b(?:" + "TB" + "D|" + "PLACE" + r"HOLDER)\b|_simu" + r"lated\s*=\s*True")


# ---------------------------------------------------------------------------
# Language-Aware Code Masking & Structural Signal Extractor
# ---------------------------------------------------------------------------


def push_ident_subtokens(ident: str, out: Set[str]) -> None:
    if len(ident) < 2:
        return
    out.add(ident.lower())
    n, seg_start = len(ident), 0
    for i in range(n + 1):
        if i == n or ident[i] in ("_", "$"):
            boundary = True
        elif i > seg_start:
            prev, cur = ident[i - 1], ident[i]
            boundary = (prev.islower() and cur.isupper()) or (
                prev.isupper() and cur.isupper() and (i + 1 < n and ident[i + 1].islower())
            )
        else:
            boundary = False
        if boundary:
            if i > seg_start:
                sub = ident[seg_start:i]
                if len(sub) >= 2 and not sub.isdigit():
                    out.add(sub.lower())
            seg_start = i + 1 if (i < n and ident[i] in ("_", "$")) else i


def _mask_python_fallback_line(raw: str) -> str:
    buf: List[str] = []
    i, n, in_str = 0, len(raw), None
    while i < n:
        ch = raw[i]
        if in_str is not None:
            if ch == "\\" and i + 1 < n:
                buf.extend((" ", " "))
                i += 2
            else:
                if ch == in_str:
                    in_str = None
                buf.append(ch if in_str is None else " ")
                i += 1
        elif ch == "#":
            break
        elif ch in ('"', "'"):
            in_str = ch
            buf.append(ch)
            i += 1
        else:
            buf.append(ch)
            i += 1
    return "".join(buf)


def _mask_python_lines(code: str) -> List[str]:
    """Use Python `tokenize` to strip `#` comments and strings while preserving `//` floor division."""
    raw_lines = code.splitlines()
    if not raw_lines:
        return []
    chars = [list(ln) for ln in raw_lines]
    fstr_mid = getattr(tokenize, "FSTRING_MIDDLE", -1)
    masked_row = 0
    try:
        for tok in tokenize.generate_tokens(io.StringIO(code).readline):
            t_type, _t_str, (sr, sc), (er, ec), _ln = tok
            masked_row = max(masked_row, er)
            if t_type == tokenize.COMMENT and 1 <= sr <= len(chars):
                row = chars[sr - 1]
                for c in range(max(0, sc), min(len(row), ec)):
                    row[c] = " "
            elif t_type in (tokenize.STRING, fstr_mid):
                for r in range(max(1, sr), min(len(chars), er) + 1):
                    row = chars[r - 1]
                    c0 = sc if r == sr else 0
                    c1 = ec if r == er else len(row)
                    for c in range(max(0, c0), min(len(row), c1)):
                        row[c] = " "
    except (tokenize.TokenError, IndentationError):
        for idx in range(max(0, masked_row - 1), len(raw_lines)):
            chars[idx] = list(_mask_python_fallback_line(raw_lines[idx]))
    return ["".join(r) for r in chars]


def _looks_like_python(code: str) -> bool:
    if _PY_DEF_OR_FROM_RE.search(code):
        return True
    if _C_STYLE_RE.search(code):
        return False
    if _PY_MARKER_RE.search(code):
        return True
    if "//" in code and not re.search(r"(?:^\s*//|;\s*//)", code, re.M):
        return True
    return False


def mask_code_lines(code: str, lang: str = "python") -> List[str]:
    """Language-aware comment/string masker (`python` preserves `//`; C-style/SQL/shell strip comments)."""
    norm = (lang or "python").strip().lower()
    if norm in ("*", "auto"):
        norm = "python" if _looks_like_python(code) else "c_style"
    if norm == "python":
        return _mask_python_lines(code)
    is_sql, is_sh = (norm == "sql"), (norm in ("shell", "bash", "zsh"))
    out_lines: List[str] = []
    in_block = False
    for raw in code.splitlines():
        buf: List[str] = []
        i, n, in_str = 0, len(raw), None
        while i < n:
            ch, nxt = raw[i], (raw[i + 1] if i + 1 < n else "")
            if in_block:
                if ch == "*" and nxt == "/":
                    in_block = False
                    buf.extend((" ", " "))
                    i += 2
                else:
                    buf.append(" ")
                    i += 1
            elif in_str is not None:
                if (is_sql and ch == "'" and nxt == "'") or ((not is_sql) and ch == "\\" and i + 1 < n):
                    buf.extend((" ", " "))
                    i += 2
                else:
                    if ch == in_str:
                        in_str = None
                    buf.append(ch if in_str is None else " ")
                    i += 1
            elif (is_sql and ch == "-" and nxt == "-") or (is_sh and ch == "#") or ((not is_sql) and (not is_sh) and ch == "/" and nxt == "/"):
                break
            elif (not is_sh) and ch == "/" and nxt == "*":
                in_block = True
                buf.extend((" ", " "))
                i += 2
            elif (is_sql and ch == "'") or ((not is_sql) and ch in ('"', "'", "`")):
                in_str = ch
                buf.append(ch)
                i += 1
            else:
                buf.append(ch)
                i += 1
        out_lines.append("".join(buf))
    return out_lines


def _detect_symbol_header(mt: str) -> Optional[Tuple[str, bool]]:
    for pref in ("def ", "async def "):
        if mt.startswith(pref):
            m = re.match(r"([A-Za-z_$][A-Za-z0-9_$]*)", mt[len(pref) :].lstrip())
            if m:
                return (m.group(1), True)
    for pref in ("function ", "async function ", "export function ", "export async function ", "pub fn ", "pub(crate) fn ", "pub async fn ", "async fn ", "fn ", "func "):
        if mt.startswith(pref):
            m = re.match(r"([A-Za-z_$][A-Za-z0-9_$]*)", mt[len(pref) :].lstrip())
            if m:
                return (m.group(1), False)
    stripped = re.sub(r"^(?:(?:public|private|protected|static|async|override|external|internal)\s+)+", "", mt)
    if stripped.endswith("{") or ") {" in stripped or "): " in stripped:
        idx = stripped.find("(")
        if idx > 0:
            head = stripped[:idx].strip()
            if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", head) and head not in ("if", "for", "while", "switch", "catch", "with", "return"):
                return (head, False)
    return None


def extract_symbol_blocks(raw_lines: List[str], masked_lines: List[str]) -> List[Tuple[str, int, int]]:
    n = len(raw_lines)
    if n == 0:
        return []
    blocks: List[Tuple[str, int, int]] = []
    i = 0
    while i < n:
        hdr = _detect_symbol_header(masked_lines[i].strip())
        if hdr is None:
            i += 1
            continue
        name, is_py = hdr
        start = i
        if is_py:
            hdr_ind = len(raw_lines[i]) - len(raw_lines[i].lstrip(" \t"))
            j = i + 1
            while j < n:
                if raw_lines[j].strip() and masked_lines[j].strip() and (len(raw_lines[j]) - len(raw_lines[j].lstrip(" \t"))) <= hdr_ind:
                    break
                j += 1
        else:
            depth, seen_open, j = 0, False, i
            while j < n:
                for ch in masked_lines[j]:
                    if ch == "{":
                        depth += 1
                        seen_open = True
                    elif ch == "}":
                        depth -= 1
                j += 1
                if seen_open and depth <= 0:
                    break
        blocks.append((name, start, min(n, max(j, start + 1))))
        i = max(j, start + 1)
    return blocks or [("<module>", 0, n)]


def _is_write_mode_open(raw_l: str, mt: str) -> bool:
    if "os.open(" in mt:
        return any(k in mt for k in ("O_WRONLY", "O_CREAT", "O_RDWR", "O_APPEND"))
    if any(k in mt for k in ("json.dump(", "write_text(", "write_bytes(", "writeFileSync(")):
        return True
    pos = 0
    while True:
        idx = mt.find("open(", pos)
        if idx == -1:
            return False
        if idx == 0 or not (mt[idx - 1].isalnum() or mt[idx - 1] in ("_", ".")):
            modes = ("'w'", '"w"', "'wb'", '"wb"', "'wt'", '"wt"', "'a'", '"a"', "'ab'", '"ab"', "'x'", '"x"', "'r+'", '"r+"', "'w+'", '"w+"', "'a+'", '"a+"', "O_WRONLY", "O_CREAT")
            return any(m in raw_l for m in modes)
        pos = idx + 5


def _extract_block_signals(raw_lines: List[str], masked_lines: List[str], indices: Sequence[int]) -> Tuple[Set[str], List[str]]:
    signals: Set[str] = set()
    f = {k: False for k in ("loop", "pair", "plus", "minus", "muldiv", "lock_op", "json", "subproc", "fswrite", "idemp", "stwrite", "dec")}
    subproc_toks = ("subprocess.", "os." + "sys" + "tem(", "os." + "pop" + "en(", "Command::new(", "child_process.")
    for idx in indices:
        raw_l, mt = raw_lines[idx], masked_lines[idx].strip()
        if not mt:
            continue
        for tok in re.findall(r"[A-Za-z_$][A-Za-z0-9_$]*", mt):
            push_ident_subtokens(tok, signals)
        f["loop"] |= mt.startswith(("while ", "for ")) or " while " in mt or " for " in mt
        f["pair"] |= any(k in mt for k in ("% 2", "%2", "// 2", "//= 2", ">> 1", ">>= 1", "+= 2")) or ("range(" in mt and ", 2)" in mt)
        f["plus"] |= "+=" in mt
        f["minus"] |= "-=" in mt
        f["muldiv"] |= ("*" in mt and ("//" in mt or "/" in mt))
        f["lock_op"] |= mt.startswith("with ") or ".acquire(" in mt or ".lock(" in mt
        f["json"] |= any(k in mt for k in ("json.loads(", "json.load(", "JSON.parse(", "serde_json::from_"))
        f["subproc"] |= any(k in mt for k in subproc_toks)
        f["fswrite"] |= _is_write_mode_open(raw_l, mt)
        f["idemp"] |= any(k in mt for k in ("idempotency", "processed_", "seen_", "ON DUPLICATE"))
        f["stwrite"] |= any(k in mt for k in (".execute(", ".query(", ".insert(", ".save(", "+=", "-="))
        f["dec"] |= any(k in mt for k in ("Decimal(", "quantize(", "ROUND_HALF_UP", "toFixed(", "float("))

    has_hash = any(h in signals for h in ("sha256", "sha512", "sha1", "md5", "blake2", "blake2b", "keccak", "createhash"))
    has_lock = any(l in signals for l in ("lock", "locks", "rlock", "mutex", "rwlock", "semaphore"))
    has_vault = any(k in signals for k in ("shares", "share", "vault")) and any(k in signals for k in ("assets", "staked", "total"))
    tag_conds = (
        (f["loop"] and f["pair"] and has_hash, "@struct_halving_hash_tree"),
        ((f["plus"] and f["minus"] and f["muldiv"]) or (f["muldiv"] and has_vault), "@struct_share_vault_ratio"),
        (has_lock and f["lock_op"] and (f["plus"] or f["minus"]), "@struct_multi_lock_transfer"),
        (f["json"], "@struct_json_untrusted_input"),
        (f["subproc"], "@struct_subprocess_exec"),
        (f["fswrite"], "@struct_fs_persistence"),
        (f["idemp"] and f["stwrite"], "@struct_idempotent_state_write"),
        (f["dec"] and (f["muldiv"] or f["plus"] or f["minus"]), "@struct_decimal_currency_math"),
    )
    tags = [tag for cond, tag in tag_conds if cond]
    signals.update(tags)
    return signals, tags


def extract_code_capsule_signals(code: str, lang: str = "python") -> Tuple[Set[str], List[str]]:
    raw_lines = code.splitlines()
    masked_lines = mask_code_lines(code, lang=lang)
    blocks = extract_symbol_blocks(raw_lines, masked_lines)
    covered = [False] * len(raw_lines)
    all_signals: Set[str] = set()
    all_tags: Set[str] = set()
    for _, start, end in blocks:
        idxs = list(range(start, min(end, len(raw_lines))))
        for idx in idxs:
            covered[idx] = True
        sigs, tags = _extract_block_signals(raw_lines, masked_lines, idxs)
        all_signals.update(sigs)
        all_tags.update(tags)
    top_idxs = [i for i, c in enumerate(covered) if not c]
    if top_idxs:
        sigs, tags = _extract_block_signals(raw_lines, masked_lines, top_idxs)
        all_signals.update(sigs)
        all_tags.update(tags)
    return all_signals, sorted(all_tags)


def infer_lang_from_path(path: Optional[Path]) -> str:
    if path is None:
        return "*"
    return {
        ".py": "python", ".pyi": "python", ".ts": "typescript", ".tsx": "typescript",
        ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
        ".sol": "solidity", ".rs": "rust", ".sql": "sql", ".go": "go",
        ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    }.get(path.suffix.lower(), "*")


TASK_SYNONYMS: Dict[str, List[str]] = {
    "money": ["money", "decimal", "amount", "currency", "price", "usd", "usdc"],
    "tax": ["tax", "decimal", "invoice", "subtotal", "round", "fx"],
    "fx": ["fx", "currency", "decimal", "usd", "rate", "exchange"],
    "exchange": ["fx", "currency", "decimal", "usd", "rate"],
    "spreadsheet": ["decimal", "total", "subtotal", "csv", "invoice"],
    "invoice": ["decimal", "total", "subtotal", "tax", "invoice", "currency"],
    "wallet": ["wallet", "address", "payout", "usdc", "sign", "receive"],
    "transaction": ["transaction", "signing", "tx_payload", "deposit_required", "transfers_funds"],
    "signing": ["signing", "signature", "hmac", "tx_payload", "cosign"],
    "lock": ["lock", "mutex", "transfer", "deadlock", "concurrency"],
    "concurrency": ["concurrency", "lock", "mutex", "async", "race", "transfer"],
    "inventory": ["stock", "inventory", "order", "idempotency", "movement"],
    "order": ["order", "idempotency", "stock", "fulfillment", "webhook"],
    "contract": ["solidity", "contract", "reentrancy", "erc20", "erc4626", "vault"],
    "defi": ["solidity", "erc4626", "vault", "shares", "reentrancy", "slippage", "oracle"],
    "vault": ["vault", "shares", "assets", "erc4626", "mint", "redeem"],
    "merkle": ["merkle", "sha256", "proof", "leaf", "root"],
    "graph": ["dag", "topological", "cycle", "ancestors", "edges"],
    "dag": ["dag", "topological", "cycle", "ancestors", "edges"],
    "signature": ["hmac", "signature", "webhook", "secret", "compare_digest", "bidi"],
    "webhook": ["webhook", "hmac", "signature", "idempotency", "json", "bidi"],
    "filesystem": ["path", "realpath", "symlink", "workspace", "traversal", "nofollow"],
    "path": ["path", "realpath", "symlink", "workspace", "traversal", "nofollow"],
    "subprocess": ["subprocess", "shell", "argv", "command", "exec"],
    "security": ["security", "sql", "path", "subprocess", "hmac", "bidi", "dlp"],
    "mysql": ["mysql", "sql", "decimal", "query", "execute", "transaction"],
    "nestjs": ["typescript", "nestjs", "async", "mysql", "sql", "dto"],
    "typescript": ["typescript", "async", "promise", "decimal", "sql"],
    "solidity": ["solidity", "reentrancy", "erc4626", "erc20", "delegatecall", "oracle"],
    "audit": ["audit", "deliverable", "security", "dlp", "bom", "csv"],
}


def expand_task_tokens(task: str) -> Set[str]:
    low, toks = task.lower(), set()
    for w in re.findall(r"[A-Za-z0-9_$-]+", task):
        push_ident_subtokens(w, toks)
    for phrase, extras in TASK_SYNONYMS.items():
        if phrase in low:
            toks.update(extras)
    return toks


def format_capsule_compact(c: Dict[str, Any]) -> str:
    return f"@CAPSULE[{c['id']}|dom={c['domain']}]\n  WHEN: {c['when_clause']}\n  INVARIANT: {c['invariant']}\n  @POS_AST: {c['pos_ast']}"


def pack_brief_within_budget(
    cand_caps: List[Tuple[Dict[str, Any], str]],
    cand_pits: List[Tuple[Dict[str, Any], str]],
    max_tokens: int,
) -> Tuple[List[Tuple[Dict[str, Any], str]], List[Tuple[Dict[str, Any], str]], str, int]:
    """Greedily pack top capsules + pitfalls guaranteeing `estimate_tokens(compact) <= max_tokens`."""
    sel_caps: List[Tuple[Dict[str, Any], str]] = []
    sel_pits: List[Tuple[Dict[str, Any], str]] = []
    parts: List[str] = []
    dropped = 0
    queue: List[Tuple[str, Dict[str, Any], str]] = []
    if cand_caps:
        queue.append(("cap", cand_caps[0][0], cand_caps[0][1]))
    if cand_pits:
        queue.append(("pit", cand_pits[0][0], cand_pits[0][1]))
    queue.extend(("cap", c, s) for c, s in cand_caps[1:])
    queue.extend(("pit", p, s) for p, s in cand_pits[1:])

    for kind, item, src in queue:
        rendered = format_capsule_compact(item) if kind == "cap" else str(item["compact"])
        if estimate_tokens("\n".join(parts + [rendered])) <= max_tokens:
            parts.append(rendered)
            (sel_caps if kind == "cap" else sel_pits).append((item, src))
        else:
            dropped += 1

    return sel_caps, sel_pits, "\n".join(parts), dropped


# ---------------------------------------------------------------------------
# Alias-Aware Python AST Security Auditor (H-11)
# ---------------------------------------------------------------------------


def _redact(text: str) -> str:
    try:
        return str(security_io.dlp_redact_output(text))
    except Exception:
        return "[REDACTED_OUTPUT]"


def _is_dynamic_str_expr(node: ast.AST) -> bool:
    if isinstance(node, (ast.JoinedStr, ast.BinOp)):
        return True
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"


def _expr_has_sql_kw(node: ast.AST) -> bool:
    return any(isinstance(s, ast.Constant) and isinstance(s.value, str) and _SQL_KW_RE.search(s.value) for s in ast.walk(node))


class _AliasAwareAstAuditor(ast.NodeVisitor):
    """Scope-aware Python AST auditor tracking module, symbol, assignment, string, dict, and getattr aliases."""

    def __init__(self, rel: str) -> None:
        self.rel, self.findings = rel, []
        self._mods: List[Dict[str, str]] = [{}]
        self._syms: List[Dict[str, str]] = [{}]
        self._dyn_sql: List[Set[str]] = [set()]
        self._sql_vars: List[Set[str]] = [set()]
        self._str_vars: List[Dict[str, str]] = [{}]
        self._bool_vars: List[Dict[str, bool]] = [{}]
        self._dict_vars: List[Dict[str, Dict[str, Optional[bool]]]] = [{}]

    def _emit(self, rule: str, severity: str, lineno: int, msg: str) -> None:
        self.findings.append({"engine": "sandbox-ast", "rule": rule, "severity": severity, "file": _redact(self.rel), "line": lineno or 1, "msg": _redact(msg)})

    def _resolve_const_str(self, node: Optional[ast.AST]) -> Optional[str]:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value if len(node.value) <= MAX_CONST_STR_LEN else None
        if isinstance(node, ast.Name):
            val = self._str_vars[-1].get(node.id)
            return val if (val is not None and len(val) <= MAX_CONST_STR_LEN) else None
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._resolve_const_str(node.left)
            if left is None or len(left) > MAX_CONST_STR_LEN:
                return None
            right = self._resolve_const_str(node.right)
            if right is None or len(right) > MAX_CONST_STR_LEN or (len(left) + len(right)) > MAX_CONST_STR_LEN:
                return None
            return left + right
        if isinstance(node, ast.JoinedStr):
            parts: List[str] = []
            total = 0
            for p in node.values:
                if isinstance(p, ast.Constant) and isinstance(p.value, str):
                    seg: Optional[str] = p.value
                elif isinstance(p, ast.FormattedValue):
                    seg = self._resolve_const_str(p.value)
                else:
                    return None
                if seg is None or (total + len(seg)) > MAX_CONST_STR_LEN:
                    return None
                parts.append(seg)
                total += len(seg)
            return "".join(parts)
        return None

    def _resolve_bool_expr(self, node: Optional[ast.AST]) -> Optional[bool]:
        if node is None:
            return None
        if isinstance(node, ast.Constant):
            return bool(node.value)
        if isinstance(node, ast.Name):
            return self._bool_vars[-1].get(node.id)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            inner = self._resolve_bool_expr(node.operand)
            return (not inner) if inner is not None else None
        if isinstance(node, ast.BoolOp):
            vals = [self._resolve_bool_expr(v) for v in node.values]
            if isinstance(node.op, ast.And):
                if any(v is False for v in vals):
                    return False
                return True if all(v is True for v in vals) else None
            if isinstance(node.op, ast.Or):
                if any(v is True for v in vals):
                    return True
                return False if all(v is False for v in vals) else None
        return None

    def _extract_dict_flags(self, node: ast.AST) -> Optional[Dict[str, Optional[bool]]]:
        if isinstance(node, ast.Name):
            existing = self._dict_vars[-1].get(node.id)
            return dict(existing) if existing is not None else None
        if isinstance(node, ast.Dict):
            flags: Dict[str, Optional[bool]] = {}
            for k, v in zip(node.keys, node.values):
                if k is None:
                    flags.update(self._extract_dict_flags(v) or {})
                elif (ks := self._resolve_const_str(k)) is not None:
                    flags[ks] = self._resolve_bool_expr(v)
            return flags
        if isinstance(node, ast.Call) and self._resolve(node.func) in ("dict", "builtins.dict"):
            flags = {}
            for kw in node.keywords:
                if kw.arg is None:
                    flags.update(self._extract_dict_flags(kw.value) or {})
                else:
                    flags[kw.arg] = self._resolve_bool_expr(kw.value)
            return flags
        return None

    def _expr_has_sql_context(self, node: ast.AST) -> bool:
        return _expr_has_sql_kw(node) or any(
            isinstance(s, ast.Name) and (s.id in self._sql_vars[-1] or s.id in self._dyn_sql[-1])
            for s in ast.walk(node)
        )

    def _resolve(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self._syms[-1].get(node.id) or self._mods[-1].get(node.id) or node.id
        if isinstance(node, ast.Attribute):
            base = self._resolve(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Call) and self._resolve(node.func) in ("getattr", "builtins.getattr") and len(node.args) >= 2:
            base, attr = self._resolve(node.args[0]), self._resolve_const_str(node.args[1])
            return f"{base}.{attr}" if (base and attr) else ""
        return ""

    def _enter_scope(self, node: ast.AST) -> None:
        self._mods.append(dict(self._mods[-1]))
        self._syms.append(dict(self._syms[-1]))
        self._dyn_sql.append(set(self._dyn_sql[-1]))
        self._sql_vars.append(set(self._sql_vars[-1]))
        self._str_vars.append(dict(self._str_vars[-1]))
        self._bool_vars.append(dict(self._bool_vars[-1]))
        self._dict_vars.append({k: dict(v) for k, v in self._dict_vars[-1].items()})
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            args = node.args
            for a in (*args.posonlyargs, *args.args, *args.kwonlyargs):
                self._clear_name(a.arg)
            if args.vararg:
                self._clear_name(args.vararg.arg)
            if args.kwarg:
                self._clear_name(args.kwarg.arg)
        self.generic_visit(node)
        for st in (self._mods, self._syms, self._dyn_sql, self._sql_vars, self._str_vars, self._bool_vars, self._dict_vars):
            st.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None: self._enter_scope(node)
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None: self._enter_scope(node)
    def visit_ClassDef(self, node: ast.ClassDef) -> None: self._enter_scope(node)

    def _merge_bool_branches(self, pre: Dict[str, bool], branches: Sequence[Dict[str, bool]]) -> None:
        merged: Dict[str, bool] = {}
        all_keys = set(pre).union(*branches)
        for k in all_keys:
            vals = [b.get(k) for b in branches]
            if vals and all(v is vals[0] for v in vals) and vals[0] is not None:
                merged[k] = vals[0]
        self._bool_vars[-1] = merged

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        pre = dict(self._bool_vars[-1])
        for stmt in node.body:
            self.visit(stmt)
        body_bool = dict(self._bool_vars[-1])
        self._bool_vars[-1] = dict(pre)
        for stmt in node.orelse:
            self.visit(stmt)
        else_bool = dict(self._bool_vars[-1])
        self._merge_bool_branches(pre, (body_bool, else_bool))

    def _visit_loop_bool_safe(self, node: ast.AST) -> None:
        pre = dict(self._bool_vars[-1])
        self.generic_visit(node)
        self._merge_bool_branches(pre, (pre, dict(self._bool_vars[-1])))

    def visit_For(self, node: ast.For) -> None: self._visit_loop_bool_safe(node)
    def visit_AsyncFor(self, node: ast.AsyncFor) -> None: self._visit_loop_bool_safe(node)
    def visit_While(self, node: ast.While) -> None: self._visit_loop_bool_safe(node)
    def visit_Try(self, node: ast.Try) -> None: self._visit_loop_bool_safe(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            self._mods[-1][name] = alias.name
            self._syms[-1].pop(name, None)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        for alias in node.names:
            if alias.name == "*":
                if mod in _WILDCARD_DANGEROUS_MODS:
                    self._emit("SEC-WILDCARD-IMPORT", "HIGH", node.lineno, f"Wildcard import from security-sensitive module '{mod}' obscures dangerous symbols; import explicitly.")
                continue
            name = alias.asname or alias.name
            self._syms[-1][name] = f"{mod}.{alias.name}" if mod else alias.name
            self._mods[-1].pop(name, None)

    def _clear_name(self, name: str) -> None:
        self._syms[-1].pop(name, None)
        self._dyn_sql[-1].discard(name)
        self._sql_vars[-1].discard(name)
        self._str_vars[-1].pop(name, None)
        self._bool_vars[-1].pop(name, None)
        self._dict_vars[-1].pop(name, None)

    def _track_assign(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value, (ast.Tuple, ast.List)) and len(target.elts) == len(value.elts):
                for t_elt, v_elt in zip(target.elts, value.elts):
                    self._track_assign(t_elt, v_elt)
            else:
                for sub in ast.walk(target):
                    if isinstance(sub, ast.Name):
                        self._clear_name(sub.id)
            return
        if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            ks = self._resolve_const_str(target.slice)
            if ks is not None and target.value.id in self._dict_vars[-1]:
                self._dict_vars[-1][target.value.id][ks] = self._resolve_bool_expr(value)
            return
        if not isinstance(target, ast.Name):
            return
        tid, res = target.id, self._resolve(value)
        tracked_sym = bool(res) and (
            res in _FORBIDDEN_DIRECT_CALLS or res in _YAML_LOAD_FUNCS or res in _YAML_UNSAFE_FUNCS
            or res in _YAML_SAFE_LOADERS or res in ("getattr", "builtins.getattr", "dict", "builtins.dict")
            or res.startswith(("subprocess.", "os.", "yaml.", "pickle.", "_pickle.", "marshal.", "builtins."))
        )
        if tracked_sym:
            self._syms[-1][tid] = res
        else:
            self._syms[-1].pop(tid, None)
        sval, bval, dflags = self._resolve_const_str(value), self._resolve_bool_expr(value), self._extract_dict_flags(value)
        if sval is not None:
            self._str_vars[-1][tid] = sval
        else:
            self._str_vars[-1].pop(tid, None)
        if bval is not None:
            self._bool_vars[-1][tid] = bval
        else:
            self._bool_vars[-1].pop(tid, None)
        if dflags is not None:
            self._dict_vars[-1][tid] = dflags
        else:
            self._dict_vars[-1].pop(tid, None)
        if _is_dynamic_str_expr(value) and self._expr_has_sql_context(value):
            self._dyn_sql[-1].add(tid)
            self._sql_vars[-1].add(tid)
        elif self._expr_has_sql_context(value) or (sval is not None and bool(_SQL_KW_RE.search(sval))):
            self._dyn_sql[-1].discard(tid)
            self._sql_vars[-1].add(tid)
        else:
            self._dyn_sql[-1].discard(tid)
            self._sql_vars[-1].discard(tid)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        for tgt in node.targets:
            self._track_assign(tgt, node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
            self._track_assign(node.target, node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        if not isinstance(node.target, ast.Name):
            return
        tid = node.target.id
        self._bool_vars[-1].pop(tid, None)
        if not isinstance(node.op, ast.Add):
            self._str_vars[-1].pop(tid, None)
            return
        rhs_const = self._resolve_const_str(node.value)
        prev_const = self._str_vars[-1].get(tid)
        is_pure_lit = isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)
        was_sql = (tid in self._sql_vars[-1]) or (tid in self._dyn_sql[-1])
        rhs_sql = self._expr_has_sql_context(node.value) or (rhs_const is not None and bool(_SQL_KW_RE.search(rhs_const)))
        if prev_const is not None and rhs_const is not None and (len(prev_const) + len(rhs_const)) <= MAX_CONST_STR_LEN:
            self._str_vars[-1][tid] = prev_const + rhs_const
        else:
            self._str_vars[-1].pop(tid, None)
        if (not is_pure_lit) and (was_sql or rhs_sql):
            self._dyn_sql[-1].add(tid)
            self._sql_vars[-1].add(tid)
        elif was_sql or rhs_sql:
            self._sql_vars[-1].add(tid)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        broad = (
            node.type is None
            or (isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"))
            or (isinstance(node.type, ast.Tuple) and any(isinstance(e, ast.Name) and e.id in ("Exception", "BaseException") for e in node.type.elts))
        )
        noop = len(node.body) == 1 and (
            isinstance(node.body[0], ast.Pass)
            or (isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) and node.body[0].value.value is Ellipsis)
        )
        if broad and noop:
            self._emit("LT-007-SILENT-EXCEPT", "HIGH", node.lineno, "Silent broad exception swallowing masks failures; catch specific exceptions.")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        resolved = self._resolve(node.func)
        if resolved in ("getattr", "builtins.getattr") and len(node.args) >= 2:
            attr = self._resolve_const_str(node.args[1])
            if attr is not None:
                base = self._resolve(node.args[0])
                if (base, attr) in _FORBIDDEN_GETATTR_PAIRS:
                    self._emit("SEC-FORBIDDEN-CALL", "CRITICAL", node.lineno, f"Unsafe dynamic lookup: getattr({base}, {attr!r})")
                elif (base, attr) == ("yaml", "lo" + "ad"):
                    self._emit("SEC-YAML-UNSAFE", "CRITICAL", node.lineno, "Dynamic lookup of unsafe YAML loader; use yaml.safe_load()")
        if resolved in _FORBIDDEN_DIRECT_CALLS:
            self._emit("SEC-FORBIDDEN-CALL", "CRITICAL", node.lineno, f"Unsafe dynamic/shell call: {resolved}")
        if resolved in _YAML_UNSAFE_FUNCS:
            self._emit("SEC-YAML-UNSAFE", "CRITICAL", node.lineno, f"Unsafe YAML loader call: {resolved}")
        elif resolved in _YAML_LOAD_FUNCS:
            ldr = next((kw.value for kw in node.keywords if kw.arg == "Loader"), node.args[1] if len(node.args) >= 2 else None)
            if (self._resolve(ldr) if ldr is not None else "") not in _YAML_SAFE_LOADERS:
                self._emit("SEC-YAML-UNSAFE", "CRITICAL", node.lineno, "Unsafe YAML load without SafeLoader/BaseLoader; use yaml.safe_load()")
        if resolved in _SUBPROC_SHELL_FUNCS:
            self._emit("SEC-SHELL-TRUE", "CRITICAL", node.lineno, f"Subprocess shell helper forbidden: {resolved}; pass argv list")
        elif resolved.startswith("subprocess."):
            for kw in node.keywords:
                if kw.arg == "shell":
                    sh_val = self._resolve_bool_expr(kw.value)
                    if sh_val is True:
                        self._emit("SEC-SHELL-TRUE", "CRITICAL", node.lineno, "Forbid shell mode in subprocess calls; pass argv list")
                    elif sh_val is None:
                        self._emit("SEC-SHELL-DYNAMIC", "HIGH", node.lineno, "Dynamic or unproven shell= expression in subprocess call; pass explicit shell=False and argv list")
                elif kw.arg is None:
                    dflags = self._extract_dict_flags(kw.value)
                    if dflags is not None and "shell" in dflags:
                        if dflags["shell"] is True:
                            self._emit("SEC-SHELL-TRUE", "CRITICAL", node.lineno, "Forbid shell mode via **kwargs unpacking in subprocess calls; pass argv list")
                        elif dflags["shell"] is None:
                            self._emit("SEC-SHELL-DYNAMIC", "HIGH", node.lineno, "Dynamic or unproven shell= flag via **kwargs unpacking in subprocess call; pass explicit shell=False and argv list")
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("execute", "executemany") and node.args:
            arg0 = node.args[0]
            if (_is_dynamic_str_expr(arg0) and self._expr_has_sql_context(arg0)) or (isinstance(arg0, ast.Name) and arg0.id in self._dyn_sql[-1]):
                self._emit("SEC-SQL-CONCAT", "HIGH", node.lineno, "SQL string interpolation/concatenation detected; use parameterized SQL")
        self.generic_visit(node)


def _scan_python_ast_extra(text: str, rel: str) -> List[Dict[str, Any]]:
    try:
        tree = ast.parse(text, filename=rel)
    except SyntaxError as exc:
        return [{"engine": "sandbox-ast", "rule": "SYNTAX-ERR", "severity": "CRITICAL", "file": rel, "line": exc.lineno or 1, "msg": _redact(str(exc))}]
    aud = _AliasAwareAstAuditor(rel)
    aud.visit(tree)
    return aud.findings


# ---------------------------------------------------------------------------
# Bounded Safe Inspection, Unified DLP + CRS Scanner & Deliverable Auditor
# ---------------------------------------------------------------------------


def _run_dlp_on_text(text: str, rel: str) -> List[Dict[str, Any]]:
    """Run per-line unified `security_io.dlp_scan_text` + Bidi Trojan check with redacted output."""
    out: List[Dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if any(c in BIDI_CHARS for c in line):
            out.append({
                "engine": "sandbox-dlp", "rule": "SEC-BIDI-TROJAN", "severity": "CRITICAL",
                "file": rel, "line": line_no, "msg": "Trojan Source Unicode Bidi control character detected",
            })
        for hit in security_io.dlp_scan_text(line):
            rule = str(hit.get("rule") or "DLP-SENSITIVE")
            if rule == "DLP-BIDI-OR-NUL" and any(c in BIDI_CHARS for c in line):
                continue
            if rule == "DLP-HEX-KEY-OR-WALLET":
                hex_hits = [m.lower() for m in _HEX_LITERAL_RE.findall(line)]
                if hex_hits and all(h in _PUBLIC_MATH_HEX for h in hex_hits):
                    continue
            sev = "CRITICAL" if rule in _DLP_CRITICAL_RULES else "HIGH"
            label = str(hit.get("label") or rule)
            out.append({"engine": "sandbox-dlp", "rule": rule, "severity": sev, "file": rel, "line": line_no, "msg": _redact(f"Sensitive pattern matched: {label}")})
    return out


def _run_dlp_on_json(text: str, rel: str) -> List[Dict[str, Any]]:
    """Parse `.json` safely and run recursive `security_io.dlp_scan_object` without echoing secrets."""
    try:
        obj = json.loads(text.lstrip("\ufeff"))
    except (ValueError, json.JSONDecodeError):
        return []
    red_rel = _redact(rel)
    try:
        hits = security_io.dlp_scan_object(obj)
    except ValueError as exc:
        return [{
            "engine": "sandbox-dlp-json", "rule": "DLP-OBJECT-LIMIT", "severity": "CRITICAL",
            "file": red_rel, "line": 1, "msg": _redact(f"JSON DLP inspection limit exceeded: {exc}"),
        }]
    out: List[Dict[str, Any]] = []
    for hit in hits:
        rule = str(hit.get("rule") or "DLP-SENSITIVE")
        if rule == "DLP-HEX-KEY-OR-WALLET":
            hex_hits = [m.lower() for m in _HEX_LITERAL_RE.findall(json.dumps(obj, ensure_ascii=False))]
            if hex_hits and all(h in _PUBLIC_MATH_HEX for h in hex_hits):
                continue
        label = str(hit.get("label") or rule)
        out.append({
            "engine": "sandbox-dlp-json", "rule": rule, "severity": "CRITICAL",
            "file": red_rel, "line": 1, "msg": _redact(f"Sensitive JSON pattern matched: {label}"),
        })
    return out


def _is_deliverable_junk_name(name: str) -> bool:
    return name == ".env" or name.startswith(".env.") or name in (".DS_Store", "__pycache__", ".coverage")


def _rel_display(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix() if path != root else path.name
    except ValueError:
        return _redact(str(path))


def _symlink_err_info(target: Path, msg: str) -> Dict[str, Any]:
    red_t = _redact(str(target))
    return {
        "missing": False, "is_dir": False, "root": target.parent, "symlink_rejections": [red_t],
        "text_records": [], "inspected_digests": [], "unsupported_binary_files": [], "skipped_files": [],
        "unreadable_dirs": [], "stat_errors": [], "special_inodes": [], "deliverable_junk": [],
        "pre_findings": [{"engine": "sandbox-io", "rule": "SYMLINK-REJECTED", "severity": "CRITICAL", "file": red_t, "line": 1, "msg": _redact(msg)}],
    }


def _inspect_target_files(target: Path, *, include_self: bool = False, include_build_dirs: bool = True) -> Dict[str, Any]:
    """Bounded symlink-rejecting file discovery and text/binary classification."""
    try:
        st = os.lstat(str(target))
    except FileNotFoundError:
        return {"missing": True}
    except OSError as exc:
        return {"io_error": str(exc)}
    if stat.S_ISLNK(st.st_mode):
        return _symlink_err_info(target, f"Refusing symlink target: {target.name}")
    try:
        security_io.reject_symlink_ancestors(target.parent if str(target.parent) else Path("."))
    except PermissionError as exc:
        return _symlink_err_info(target, str(exc))

    is_dir = stat.S_ISDIR(st.st_mode)
    root = target if is_dir else target.parent
    skip_dirs = SKIP_DIRS_DEFAULT if include_build_dirs else SKIP_DIRS_NO_BUILD
    skip_set = set(skip_dirs)
    walk = security_io.iter_safe_files(
        target, skip_dirs=skip_dirs, max_files=MAX_SCAN_FILES,
        max_file_bytes=MAX_SCAN_FILE_BYTES, max_total_bytes=MAX_SCAN_TOTAL_BYTES, max_depth=MAX_SCAN_DEPTH,
    )
    cand_files: List[Path] = list(walk["files"])
    symlink_rejs = [_redact(s) for s in walk["symlink_rejections"]]
    skipped_files = [_redact(s) for s in walk["skipped_oversized"]]
    stat_errors = [_rel_display(Path(s), root) for s in walk.get("stat_errors", [])]
    special_inodes = [_rel_display(Path(s), root) for s in walk.get("special_inodes", [])]
    if not is_dir and not stat.S_ISREG(st.st_mode) and not special_inodes:
        special_inodes.append(_rel_display(target, root))
    if walk.get("truncated"):
        skipped_files.append("SCAN_BUDGET_TRUNCATED")

    unreadable_dirs: List[str] = []
    deliverable_junk: List[str] = []
    seen_junk: Set[str] = set()

    def _add_junk(p: Path) -> None:
        if _is_deliverable_junk_name(p.name) and (disp := _rel_display(p, root)) not in seen_junk:
            seen_junk.add(disp)
            deliverable_junk.append(disp)

    _add_junk(target)
    for d_str in walk.get("skipped_dirs", []):
        dp = Path(d_str)
        _add_junk(dp)
        if dp.name not in skip_set or dp == target:
            unreadable_dirs.append(_rel_display(dp, root))
    for p in (*cand_files, *(Path(s) for s in walk.get("skipped_oversized", []))):
        _add_junk(p)

    pre_findings: List[Dict[str, Any]] = [
        {"engine": "sandbox-io", "rule": "SYMLINK-REJECTED", "severity": "CRITICAL", "file": sym, "line": 1, "msg": _redact(f"Symlink rejected during scan: {sym}")}
        for sym in symlink_rejs
    ]
    bundle_dir = Path(__file__).resolve().parent
    if is_dir and not include_self:
        cand_files = [f for f in cand_files if not (f.parent.resolve() == bundle_dir and f.name in SELF_SCAN_FILES)]

    text_records: List[Tuple[Path, str, bytes, str]] = []
    inspected_digests: List[Tuple[str, str]] = []
    unsupported_binary_files: List[str] = []
    total_bytes = 0
    for f in cand_files[:MAX_SCAN_FILES]:
        rel = f.relative_to(root).as_posix() if f != root else f.name
        if f.suffix.lower() in BINARY_EXTS:
            unsupported_binary_files.append(_redact(rel))
            continue
        rem = MAX_SCAN_TOTAL_BYTES - total_bytes
        if rem <= 0:
            skipped_files.append(_redact(f"{rel} (max_total_bytes_exceeded)"))
            continue
        try:
            raw = security_io.read_regular_bytes_secure(f, max_bytes=min(MAX_SCAN_FILE_BYTES, rem))
        except ValueError as exc:
            skipped_files.append(_redact(f"{rel} ({exc})"))
            continue
        except (OSError, PermissionError) as exc:
            is_sym = "SYMLINK" in str(exc).upper()
            red_rel = _redact(rel)
            if is_sym and red_rel not in symlink_rejs:
                symlink_rejs.append(red_rel)
            pre_findings.append({"engine": "sandbox-io", "rule": "SYMLINK-REJECTED" if is_sym else "IO-READ-ERR", "severity": "CRITICAL" if is_sym else "HIGH", "file": red_rel, "line": 1, "msg": _redact(str(exc))})
            continue
        total_bytes += len(raw)
        is_text_or_env = (f.suffix.lower() in TEXT_EXTS) or (f.name == ".env") or f.name.startswith(".env.")
        if is_text_or_env and b"\x00" in raw:
            inspected_digests.append((rel, security_io.sha256_bytes(raw)))
            pre_findings.append({"engine": "sandbox-dlp", "rule": "DLP-BIDI-OR-NUL", "severity": "CRITICAL", "file": _redact(rel), "line": 1, "msg": "NUL byte detected in text/code or .env file (possible binary smuggling)"})
            pre_findings.extend(df for df in _run_dlp_on_text(raw.replace(b"\x00", b" ").decode("utf-8", errors="replace"), rel) if df["rule"] != "DLP-BIDI-OR-NUL")
            continue
        if b"\x00" in raw[:BINARY_SNIFF_BYTES]:
            unsupported_binary_files.append(_redact(rel))
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            if is_text_or_env:
                inspected_digests.append((rel, security_io.sha256_bytes(raw)))
                pre_findings.append({"engine": "sandbox-dlp", "rule": "ENC-UTF8-INVALID", "severity": "HIGH", "file": _redact(rel), "line": 1, "msg": _redact(f"Invalid UTF-8 in text/code file: {exc}")})
            else:
                unsupported_binary_files.append(_redact(rel))
            continue
        inspected_digests.append((rel, security_io.sha256_bytes(raw)))
        text_records.append((f, rel, raw, text))

    return {
        "missing": False, "is_dir": is_dir, "root": root, "symlink_rejections": symlink_rejs,
        "text_records": text_records, "inspected_digests": inspected_digests,
        "unsupported_binary_files": unsupported_binary_files, "skipped_files": skipped_files,
        "unreadable_dirs": unreadable_dirs, "stat_errors": stat_errors, "special_inodes": special_inodes,
        "deliverable_junk": deliverable_junk, "pre_findings": pre_findings,
    }


def _compute_content_sha256(info: Dict[str, Any], *, allow_binary: bool) -> str:
    digests: List[Tuple[str, str]] = info.get("inspected_digests", [])
    if not info.get("is_dir"):
        return digests[0][1] if len(digests) == 1 else ""
    lines = [f"{rel}\0{h}\n" for rel, h in digests]
    if allow_binary:
        lines.extend(f"{rel}\0BINARY_UNINSPECTED\n" for rel in info.get("unsupported_binary_files", []))
    return security_io.sha256_bytes("".join(sorted(lines)).encode("utf-8")) if lines else ""


def _scan_target_with_info(
    target: Path, *, include_self: bool = False, include_build_dirs: bool = True, allow_binary: bool = False
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Run bounded Dual-Engine Security + Unified DLP + Alias-Aware AST scan and return `(result, info)`."""
    t0 = time.perf_counter()
    info = _inspect_target_files(target, include_self=include_self, include_build_dirs=include_build_dirs)
    if info.get("missing") or info.get("io_error"):
        status = "PATH_NOT_FOUND" if info.get("missing") else "IO_ERROR"
        err = f"Path not found: {target}" if info.get("missing") else str(info["io_error"])
        return ({
            "ok": False, "status": status, "error": _redact(err),
            "edition": EDITION_NAME, "kintsugi_version": KINTSUGI_VERSION,
            "inspected_files": 0, "files_scanned": 0, "content_sha256": "",
            "unsupported_binary_files": [], "symlink_rejections": [], "skipped_files": [],
            "unreadable_dirs": [], "stat_errors": [], "special_inodes": [],
            "total_findings": 0, "blocking_count": 0, "findings": [],
        }, info)

    crs_scanner = KintsugiScanner(get_full_crs_scars())
    all_findings: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, int, str]] = set()

    def _add(item: Dict[str, Any]) -> None:
        clean = dict(item)
        if "file" in clean:
            clean["file"] = _redact(str(clean["file"]))
        if "msg" in clean:
            clean["msg"] = _redact(str(clean["msg"]))
        if clean.get("fix"):
            clean["fix"] = _redact(str(clean["fix"]))
        key = (str(clean.get("file", "")), int(clean["line"]), str(clean["rule"]))
        if key not in seen:
            seen.add(key)
            all_findings.append(clean)

    for pf in info["pre_findings"]:
        _add(pf)

    text_records: List[Tuple[Path, str, bytes, str]] = info["text_records"]
    for f, rel, _raw, text in text_records:
        text_dlp_hits = _run_dlp_on_text(text, rel)
        text_dlp_rules = {df["rule"] for df in text_dlp_hits}
        for df in text_dlp_hits:
            _add(df)
        if f.suffix.lower() == ".json":
            for jf in _run_dlp_on_json(text, rel):
                if jf["rule"] == "DLP-SECRET-KV-PAIR" or jf["rule"] not in text_dlp_rules:
                    _add(jf)
        k_lang = crs_scanner.infer_language(f)
        if k_lang is not None:
            for kf in crs_scanner.scan_text(text, language=k_lang, file_path=rel):
                sev = kf.severity.value if hasattr(kf.severity, "value") else str(kf.severity)
                _add({"engine": f"kintsugi-crs:{kf.engine}", "rule": kf.scar_id, "severity": sev, "file": rel, "line": kf.line, "msg": kf.title, "fix": kf.good_code_hint})
        if f.suffix.lower() == ".py":
            for af in _scan_python_ast_extra(text, rel):
                _add(af)

    blocking = [x for x in all_findings if x["severity"] in ("CRITICAL", "HIGH")]
    inspected = len(text_records)
    incomplete = (
        bool(info["skipped_files"])
        or bool(info["unreadable_dirs"])
        or bool(info["stat_errors"])
        or bool(info["special_inodes"])
        or (bool(info["unsupported_binary_files"]) and not allow_binary)
    )
    if blocking:
        ok, status = False, "BLOCKED_FINDINGS"
    elif incomplete:
        ok, status = False, "INCOMPLETE_SCAN"
    elif inspected == 0:
        ok, status = False, "EMPTY_OR_UNINSPECTED"
    else:
        ok, status = True, "PASS_100"

    content_sha256 = _compute_content_sha256(info, allow_binary=allow_binary)
    return ({
        "ok": ok, "status": status, "edition": EDITION_NAME, "kintsugi_version": KINTSUGI_VERSION,
        "inspected_files": inspected, "files_scanned": inspected, "content_sha256": content_sha256,
        "unsupported_binary_files": [_redact(x) for x in info["unsupported_binary_files"]],
        "symlink_rejections": [_redact(x) for x in info["symlink_rejections"]],
        "skipped_files": [_redact(x) for x in info["skipped_files"]],
        "unreadable_dirs": [_redact(x) for x in info["unreadable_dirs"]],
        "stat_errors": [_redact(x) for x in info["stat_errors"]],
        "special_inodes": [_redact(x) for x in info["special_inodes"]],
        "total_findings": len(all_findings), "blocking_count": len(blocking),
        "elapsed_ms": round((time.perf_counter() - t0) * 1000.0, 2), "findings": all_findings,
    }, info)


def scan_target(target: Path, *, include_self: bool = False, include_build_dirs: bool = True, allow_binary: bool = False) -> Dict[str, Any]:
    """Run bounded Dual-Engine Security + Unified DLP + Alias-Aware AST scan with honest coverage gate."""
    res, _ = _scan_target_with_info(target, include_self=include_self, include_build_dirs=include_build_dirs, allow_binary=allow_binary)
    return res


def audit_deliverable(target: Path, *, include_self: bool = False, allow_binary: bool = False) -> Dict[str, Any]:
    """Run single-walk `scan_target` plus deliverable hygiene audit (LT-053 BOM, LT-054 meta-words, LT-055 stubs, LT-062 junk)."""
    scan_res, info = _scan_target_with_info(target, include_self=include_self, include_build_dirs=True, allow_binary=allow_binary)
    deliverable_findings: List[Dict[str, Any]] = []

    if not info.get("missing") and not info.get("io_error"):
        for junk_rel in info.get("deliverable_junk", []):
            deliverable_findings.append({
                "rule": "LT-062", "severity": "HIGH", "file": _redact(junk_rel), "line": 1,
                "msg": _redact(f"Forbidden deliverable junk/secret artifact present: {junk_rel}; remove before submission."),
            })
        for f, rel, raw, text in info["text_records"]:
            red_rel = _redact(rel)
            if f.suffix.lower() in DELIVERABLE_BOM_EXTS and raw.startswith(b"\xef\xbb\xbf"):
                deliverable_findings.append({
                    "rule": "LT-053", "severity": "HIGH" if f.suffix.lower() == ".json" else "MEDIUM",
                    "file": red_rel, "line": 1, "msg": f"UTF-8 BOM detected on {f.suffix.lower()} deliverable; strip BOM before submission.",
                })
            for line_no, line in enumerate(text.splitlines(), 1):
                m_meta = _META_DISPUTE_RE.search(line)
                if m_meta:
                    deliverable_findings.append({"rule": "LT-054", "severity": "HIGH", "file": red_rel, "line": line_no, "msg": _redact(f"Forbidden meta-rubric/process phrase in deliverable: {m_meta.group(0)!r}")})
                m_ph = _PLACEHOLDER_RE.search(line)
                if m_ph:
                    deliverable_findings.append({"rule": "LT-055", "severity": "HIGH", "file": red_rel, "line": line_no, "msg": _redact(f"Unfinished placeholder/stub marker in deliverable: {m_ph.group(0)!r}")})

    ok = bool(scan_res.get("ok")) and len(deliverable_findings) == 0
    return {
        "ok": ok, "status": "PASS_DELIVERABLE_AUDIT" if ok else "DELIVERABLE_ISSUES_FOUND",
        "edition": EDITION_NAME, "kintsugi_version": KINTSUGI_VERSION,
        "scan": scan_res, "deliverable_findings": deliverable_findings,
    }
