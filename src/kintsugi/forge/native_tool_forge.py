"""Stage 3 Autonomous Native Tool Forge (`kintsugi.forge.native_tool_forge`).

Implements the strict monotonic forge lifecycle:
  PROPOSED -> SPECIFIED -> REFERENCE_VERIFIED -> GENERATED -> COMPILED ->
  SANDBOX_TESTED -> DIFFERENTIAL_VERIFIED -> BENCHMARKED -> SHADOW -> VERIFIED

Enforces the escalation ladder (`existing tool -> adapter -> composition ->
python reference -> rust/c -> simd [if benchmarked beneficial] -> assembly
[if end-to-end proven]`), static safety checks, empirical OS sandbox isolation,
100+ seeded differential/boundary/fuzz verification, warmup+measured benchmarking,
atomic manifest provenance persistence, and zero in-process FFI injection.
"""

from __future__ import annotations

import hmac
import inspect
import json
import os
import random
import re
import secrets
import shutil
import stat
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from kintsugi.capability.capability_graph import CapabilityGraph, tool_violates_security_context
from kintsugi.capability.contracts_v2 import (
    EffectContract,
    ForgeState,
    PortContract,
    ToolBuild,
)
from kintsugi.capability.schemas import (
    CapabilityGap,
    ExecutionStatus,
    SecurityContext,
    SecurityProfile,
    ToolSpec,
    TrustStatus,
    canonical_json_dumps,
    compute_tool_spec_security_digest,
    redact_secrets_in_text,
    redact_secrets_in_value,
    sha256_digest,
    validate_safe_text,
    validate_tool_id,
)
from kintsugi.capability.tool_registry import AttestationAuthority, ToolRegistry
from kintsugi.forge.build_manifest import BuildManifestStore, RollbackResult
from kintsugi.forge.tool_benchmark import BenchmarkReport, ToolBenchmark
from kintsugi.forge.tool_sandbox import SandboxExecutionResult, SandboxReceipt, ToolSandbox
from kintsugi.shield import (
    TROJAN_UNICODE_RE,
    assert_not_symlink,
    atomic_write_text,
    scan_artifact_egress,
)

FORGE_VERIFIER_ID = "kintsugi.native_tool_forge"
DEFAULT_FORGED_TOOLS_REL_DIR = ".kintsugi/forged_tools"

_FORBIDDEN_C_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("FORBIDDEN_C_SYSTEM_CALL", re.compile(r"\b(?:system|popen|execve|execl|execlp|execle|execv|execvp|fork|vfork)\s*\(")),
    ("FORBIDDEN_C_DYNAMIC_LOAD", re.compile(r"\b(?:dlopen|dlsym|dlclose)\s*\(")),
    ("FORBIDDEN_C_NETWORK_CALL", re.compile(r"\b(?:socket|connect|bind|listen|accept|sendto|recvfrom|getaddrinfo)\s*\(")),
    ("FORBIDDEN_C_NETWORK_HEADER", re.compile(r"#\s*include\s*<\s*(?:sys/socket\.h|netinet/|arpa/inet\.h|netdb\.h)")),
    ("FORBIDDEN_C_UNSAFE_STRING", re.compile(r"\b(?:strcpy|strcat|sprintf|vsprintf|gets|scanf|mktemp)\s*\(")),
    ("FORBIDDEN_C_INLINE_ASM", re.compile(r"\b(?:__asm__|__asm|asm)\b")),
)

_FORBIDDEN_RUST_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("FORBIDDEN_RUST_PROCESS", re.compile(r"\bstd::process::Command\b")),
    ("FORBIDDEN_RUST_NETWORK", re.compile(r"\bstd::net::")),
    ("FORBIDDEN_RUST_UNSAFE_BLOCK", re.compile(r"\bunsafe\s*\{")),
    ("FORBIDDEN_RUST_FFI_LIBC", re.compile(r"\blibc::")),
)


class ForgeEscalationTier(str, Enum):
    """Strict escalation ladder priority for resolving or forging capabilities."""

    EXISTING_TOOL = "existing_tool"
    ADAPTER = "adapter"
    COMPOSITION = "composition"
    PYTHON_REFERENCE = "python_reference"
    RUST_OR_C = "rust_c"
    SIMD = "simd"
    ASSEMBLY = "assembly"


ESCALATION_LADDER_ORDER: Tuple[ForgeEscalationTier, ...] = (
    ForgeEscalationTier.EXISTING_TOOL,
    ForgeEscalationTier.ADAPTER,
    ForgeEscalationTier.COMPOSITION,
    ForgeEscalationTier.PYTHON_REFERENCE,
    ForgeEscalationTier.RUST_OR_C,
    ForgeEscalationTier.SIMD,
    ForgeEscalationTier.ASSEMBLY,
)


@dataclass(frozen=True)
class EscalationDecision:
    """Recorded decision explaining why the forge chose a specific ladder tier."""

    selected_tier: ForgeEscalationTier
    ladder_trace: List[Dict[str, Any]]
    existing_tool_id: Optional[str] = None
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return redact_secrets_in_value(
            {
                "selected_tier": self.selected_tier.value,
                "ladder_trace": list(self.ladder_trace),
                "existing_tool_id": self.existing_tool_id,
                "reason": self.reason,
            }
        )


def scan_forged_source_safety(
    source_code: str,
    *,
    language: str = "c",
    allow_simd: bool = False,
    allow_assembly: bool = False,
) -> Tuple[bool, List[str]]:
    """Run static safety + secret-egress scans before compiling any generated source."""
    reasons: List[str] = []
    if not isinstance(source_code, str) or not source_code.strip():
        return False, ["EMPTY_SOURCE_CODE"]
    if "\x00" in source_code or TROJAN_UNICODE_RE.search(source_code):
        reasons.append("TROJAN_OR_NUL_IN_SOURCE")

    egress = scan_artifact_egress(source_code, context="forge_source")
    if not egress["ok"]:
        reasons.append("EGRESS_SECRET_OR_DLP_IN_SOURCE")

    norm_lang = str(language or "c").strip().lower()
    if norm_lang == "c":
        for rule_name, pat in _FORBIDDEN_C_PATTERNS:
            if rule_name == "FORBIDDEN_C_INLINE_ASM" and allow_assembly:
                continue
            if pat.search(source_code):
                reasons.append(rule_name)
        if not allow_simd and re.search(r"<(?:arm_neon|immintrin|xmmintrin|emmintrin)\.h>", source_code):
            reasons.append("FORBIDDEN_UNBENCHMARKED_SIMD_INTRINSICS")
    elif norm_lang == "rust":
        for rule_name, pat in _FORBIDDEN_RUST_PATTERNS:
            if rule_name == "FORBIDDEN_RUST_UNSAFE_BLOCK" and (allow_simd or allow_assembly):
                continue
            if pat.search(source_code):
                reasons.append(rule_name)
    else:
        reasons.append(f"UNSUPPORTED_FORGE_LANGUAGE:{norm_lang}")

    return len(reasons) == 0, reasons


def parse_kvpipe_v1_python(raw_input: Union[str, bytes]) -> Dict[str, Any]:
    """Pure Python reference oracle for `kvpipe.v1` structured logs (`KEY=VAL|...`)."""
    raw_bytes = raw_input if isinstance(raw_input, bytes) else str(raw_input).encode("utf-8", errors="replace")
    records: List[Dict[str, Any]] = []
    parsed_count = 0
    malformed_count = 0
    total_lines = 0

    line_num = 0
    pos = 0
    total_len = len(raw_bytes)
    while pos < total_len:
        nl = raw_bytes.find(b"\n", pos)
        if nl == -1:
            line = raw_bytes[pos:total_len]
            pos = total_len
        else:
            line = raw_bytes[pos:nl]
            pos = nl + 1
        line_num += 1
        if line.endswith(b"\r"):
            line = line[:-1]
        if not line:
            continue

        total_lines += 1
        segments = line.split(b"|")
        fields: Dict[str, str] = {}
        bad_line = False
        for seg in segments:
            if not seg:
                bad_line = True
                break
            eq = seg.find(b"=")
            if eq <= 0:
                bad_line = True
                break
            key_bytes = seg[:eq]
            val_bytes = seg[eq + 1 :]
            if any(b <= 0x20 or b >= 0x7F for b in key_bytes):
                bad_line = True
                break
            key_str = key_bytes.decode("ascii")
            val_str = val_bytes.decode("utf-8", errors="replace")
            fields[key_str] = val_str

        if bad_line or not fields:
            malformed_count += 1
        else:
            parsed_count += 1
            ordered_fields = {k: fields[k] for k in sorted(fields.keys())}
            records.append({"line": line_num, "fields": ordered_fields})

    return {
        "format": "kvpipe.v1",
        "parsed": parsed_count,
        "malformed": malformed_count,
        "total_lines": total_lines,
        "records": records,
    }


_KVPIPE_V1_C99_SOURCE = r"""
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT_BYTES (64u * 1024u * 1024u)

typedef struct {
    const uint8_t *key;
    size_t key_len;
    const uint8_t *val;
    size_t val_len;
} KVPair;

typedef struct {
    size_t line_num;
    KVPair *pairs;
    size_t pair_count;
} LogRecord;

static int cmp_kvpair(const void *a, const void *b) {
    const KVPair *pa = (const KVPair *)a;
    const KVPair *pb = (const KVPair *)b;
    size_t min_len = pa->key_len < pb->key_len ? pa->key_len : pb->key_len;
    int r = memcmp(pa->key, pb->key, min_len);
    if (r != 0) return r;
    if (pa->key_len < pb->key_len) return -1;
    if (pa->key_len > pb->key_len) return 1;
    return 0;
}

static void write_replacement_char(FILE *out) {
    static const uint8_t ufffd[3] = {0xEFu, 0xBFu, 0xBDu};
    fwrite(ufffd, 1u, 3u, out);
}

static void write_json_escaped_bytes(FILE *out, const uint8_t *s, size_t n) {
    fputc('"', out);
    size_t i = 0;
    while (i < n) {
        uint8_t b0 = s[i];
        if (b0 < 0x80u) {
            if (b0 == '"') {
                fputs("\\\"", out);
            } else if (b0 == '\\') {
                fputs("\\\\", out);
            } else if (b0 == '\b') {
                fputs("\\b", out);
            } else if (b0 == '\f') {
                fputs("\\f", out);
            } else if (b0 == '\n') {
                fputs("\\n", out);
            } else if (b0 == '\r') {
                fputs("\\r", out);
            } else if (b0 == '\t') {
                fputs("\\t", out);
            } else if (b0 < 0x20u) {
                fprintf(out, "\\u%04x", (unsigned int)b0);
            } else {
                fputc((int)b0, out);
            }
            i += 1u;
            continue;
        }
        if (b0 >= 0xC2u && b0 <= 0xDFu) {
            if (i + 1u < n && (s[i + 1u] & 0xC0u) == 0x80u) {
                fwrite(&s[i], 1u, 2u, out);
                i += 2u;
            } else {
                write_replacement_char(out);
                i += 1u;
            }
            continue;
        }
        if (b0 >= 0xE0u && b0 <= 0xEFu) {
            int b1_ok = 0;
            if (i + 1u < n) {
                uint8_t b1 = s[i + 1u];
                if (b0 == 0xE0u) {
                    b1_ok = (b1 >= 0xA0u && b1 <= 0xBFu);
                } else if (b0 == 0xEDu) {
                    b1_ok = (b1 >= 0x80u && b1 <= 0x9Fu);
                } else {
                    b1_ok = ((b1 & 0xC0u) == 0x80u);
                }
            }
            if (b1_ok) {
                if (i + 2u < n && (s[i + 2u] & 0xC0u) == 0x80u) {
                    fwrite(&s[i], 1u, 3u, out);
                    i += 3u;
                } else {
                    write_replacement_char(out);
                    i += 2u;
                }
            } else {
                write_replacement_char(out);
                i += 1u;
            }
            continue;
        }
        if (b0 >= 0xF0u && b0 <= 0xF4u) {
            int b1_ok = 0;
            if (i + 1u < n) {
                uint8_t b1 = s[i + 1u];
                if (b0 == 0xF0u) {
                    b1_ok = (b1 >= 0x90u && b1 <= 0xBFu);
                } else if (b0 == 0xF4u) {
                    b1_ok = (b1 >= 0x80u && b1 <= 0x8Fu);
                } else {
                    b1_ok = ((b1 & 0xC0u) == 0x80u);
                }
            }
            if (b1_ok) {
                if (i + 2u < n && (s[i + 2u] & 0xC0u) == 0x80u) {
                    if (i + 3u < n && (s[i + 3u] & 0xC0u) == 0x80u) {
                        fwrite(&s[i], 1u, 4u, out);
                        i += 4u;
                    } else {
                        write_replacement_char(out);
                        i += 3u;
                    }
                } else {
                    write_replacement_char(out);
                    i += 2u;
                }
            } else {
                write_replacement_char(out);
                i += 1u;
            }
            continue;
        }
        write_replacement_char(out);
        i += 1u;
    }
    fputc('"', out);
}

static uint8_t *read_all_stream(FILE *in_fp, size_t *out_len) {
    size_t cap = 4096u;
    size_t len = 0u;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) return NULL;
    for (;;) {
        if (len == cap) {
            if (cap >= MAX_INPUT_BYTES) {
                free(buf);
                return NULL;
            }
            size_t next_cap = cap * 2u;
            if (next_cap > MAX_INPUT_BYTES) next_cap = MAX_INPUT_BYTES;
            uint8_t *nb = (uint8_t *)realloc(buf, next_cap);
            if (!nb) {
                free(buf);
                return NULL;
            }
            buf = nb;
            cap = next_cap;
        }
        size_t got = fread(buf + len, 1u, cap - len, in_fp);
        len += got;
        if (got == 0u) {
            if (ferror(in_fp)) {
                free(buf);
                return NULL;
            }
            break;
        }
    }
    *out_len = len;
    return buf;
}

static int parse_line_pairs(
    const uint8_t *line,
    size_t line_len,
    KVPair **out_pairs,
    size_t *out_count
) {
    size_t cap = 8u;
    size_t count = 0u;
    KVPair *pairs = (KVPair *)malloc(cap * sizeof(KVPair));
    if (!pairs) return -1;

    size_t seg_start = 0u;
    for (size_t idx = 0u; idx <= line_len; idx++) {
        if (idx < line_len && line[idx] != (uint8_t)'|') {
            continue;
        }
        size_t seg_len = idx - seg_start;
        if (seg_len == 0u) {
            free(pairs);
            return 1;
        }
        const uint8_t *seg = line + seg_start;
        const uint8_t *eq_ptr = (const uint8_t *)memchr(seg, '=', seg_len);
        if (!eq_ptr || eq_ptr == seg) {
            free(pairs);
            return 1;
        }
        size_t key_len = (size_t)(eq_ptr - seg);
        for (size_t k = 0u; k < key_len; k++) {
            uint8_t kb = seg[k];
            if (kb <= 0x20u || kb >= 0x7Fu) {
                free(pairs);
                return 1;
            }
        }
        const uint8_t *val_ptr = eq_ptr + 1;
        size_t val_len = seg_len - key_len - 1u;

        int updated = 0;
        for (size_t p = 0u; p < count; p++) {
            if (pairs[p].key_len == key_len && memcmp(pairs[p].key, seg, key_len) == 0) {
                pairs[p].val = val_ptr;
                pairs[p].val_len = val_len;
                updated = 1;
                break;
            }
        }
        if (!updated) {
            if (count == cap) {
                if (cap > SIZE_MAX / 2u / sizeof(KVPair)) {
                    free(pairs);
                    return -1;
                }
                size_t next_cap = cap * 2u;
                KVPair *np = (KVPair *)realloc(pairs, next_cap * sizeof(KVPair));
                if (!np) {
                    free(pairs);
                    return -1;
                }
                pairs = np;
                cap = next_cap;
            }
            pairs[count].key = seg;
            pairs[count].key_len = key_len;
            pairs[count].val = val_ptr;
            pairs[count].val_len = val_len;
            count += 1u;
        }
        seg_start = idx + 1u;
    }

    if (count == 0u) {
        free(pairs);
        return 1;
    }
    qsort(pairs, count, sizeof(KVPair), cmp_kvpair);
    *out_pairs = pairs;
    *out_count = count;
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOFBF, 65536u);
    FILE *in_fp = stdin;
    if (argc > 1 && argv[1] && argv[1][0] != '\0') {
        in_fp = fopen(argv[1], "rb");
        if (!in_fp) {
            fprintf(stderr, "OPEN_FAILED\n");
            return 2;
        }
    }

    size_t total_len = 0u;
    uint8_t *buf = read_all_stream(in_fp, &total_len);
    if (in_fp != stdin) {
        fclose(in_fp);
    }
    if (!buf) {
        fprintf(stderr, "READ_FAILED\n");
        return 3;
    }

    size_t rec_cap = 16u;
    size_t rec_count = 0u;
    LogRecord *records = (LogRecord *)malloc(rec_cap * sizeof(LogRecord));
    if (!records) {
        free(buf);
        return 4;
    }

    size_t parsed_count = 0u;
    size_t malformed_count = 0u;
    size_t total_lines = 0u;
    size_t line_num = 0u;
    size_t pos = 0u;

    while (pos < total_len) {
        const uint8_t *nl_ptr = (const uint8_t *)memchr(buf + pos, '\n', total_len - pos);
        size_t end = nl_ptr ? (size_t)(nl_ptr - buf) : total_len;
        size_t next_pos = nl_ptr ? (end + 1u) : total_len;
        line_num += 1u;
        size_t line_end = end;
        if (line_end > pos && buf[line_end - 1u] == (uint8_t)'\r') {
            line_end -= 1u;
        }
        size_t line_len = line_end - pos;
        if (line_len == 0u) {
            pos = next_pos;
            continue;
        }
        total_lines += 1u;
        KVPair *pairs = NULL;
        size_t pair_count = 0u;
        int rc = parse_line_pairs(buf + pos, line_len, &pairs, &pair_count);
        if (rc < 0) {
            for (size_t i = 0u; i < rec_count; i++) free(records[i].pairs);
            free(records);
            free(buf);
            return 5;
        }
        if (rc > 0) {
            malformed_count += 1u;
        } else {
            parsed_count += 1u;
            if (rec_count == rec_cap) {
                size_t next_cap = rec_cap * 2u;
                LogRecord *nr = (LogRecord *)realloc(records, next_cap * sizeof(LogRecord));
                if (!nr) {
                    free(pairs);
                    for (size_t i = 0u; i < rec_count; i++) free(records[i].pairs);
                    free(records);
                    free(buf);
                    return 6;
                }
                records = nr;
                rec_cap = next_cap;
            }
            records[rec_count].line_num = line_num;
            records[rec_count].pairs = pairs;
            records[rec_count].pair_count = pair_count;
            rec_count += 1u;
        }
        pos = next_pos;
    }

    printf(
        "{\"format\":\"kvpipe.v1\",\"parsed\":%zu,\"malformed\":%zu,\"total_lines\":%zu,\"records\":[",
        parsed_count,
        malformed_count,
        total_lines
    );
    for (size_t i = 0u; i < rec_count; i++) {
        if (i > 0u) fputc(',', stdout);
        printf("{\"line\":%zu,\"fields\":{", records[i].line_num);
        for (size_t j = 0u; j < records[i].pair_count; j++) {
            if (j > 0u) fputc(',', stdout);
            write_json_escaped_bytes(stdout, records[i].pairs[j].key, records[i].pairs[j].key_len);
            fputc(':', stdout);
            write_json_escaped_bytes(stdout, records[i].pairs[j].val, records[i].pairs[j].val_len);
        }
        fputs("}}", stdout);
    }
    fputs("]}\n", stdout);

    for (size_t i = 0u; i < rec_count; i++) {
        free(records[i].pairs);
    }
    free(records);
    free(buf);
    return 0;
}
"""


def generate_kvpipe_v1_boundary_cases() -> List[Tuple[str, bytes]]:
    """Return explicit boundary test vectors: empty, 1-byte, truncated, malformed, huge line."""
    huge_val = b"X" * 70000
    return [
        ("empty", b""),
        ("single_newline", b"\n"),
        ("one_byte_pipe", b"|"),
        ("one_byte_eq", b"="),
        ("one_byte_char", b"A"),
        ("truncated_no_nl", b"TS=2026-11-21T19:00:00Z|LEVEL=INFO|MSG=half"),
        ("truncated_trailing_pipe", b"TS=2026-11-21T19:00:00Z|LEVEL=INFO|"),
        ("malformed_no_equals", b"JUST_RAW_TEXT"),
        ("malformed_empty_key", b"=VALUE_WITHOUT_KEY"),
        ("malformed_whitespace_key", b"BAD KEY=1|GOOD=2"),
        ("duplicate_key_and_equals_in_val", b"A=1|B=x=y==|A=2\n"),
        ("crlf_and_json_escapes", b'MSG="hello\\world"\tline|TAG=ok\r\n\r\nK=1\n'),
        ("huge_single_line_70kb", b"KEY=1|BLOB=" + huge_val + b"|END=ok\n"),
        ("embedded_nul_and_invalid_utf8", b"MSG=a\x00b\xff\xfe\x80|OK=1\n"),
    ]


def generate_kvpipe_v1_fuzz_cases(*, seed: int = 20261121, count: int = 120) -> List[bytes]:
    """Generate `count` deterministic seeded fuzz byte payloads covering valid + edge inputs."""
    rng = random.Random(seed)
    keys = ["TS", "LEVEL", "SERVICE", "TRACE", "CODE", "MSG", "LAT_MS", "REGION"]
    vals = ["INFO", "WARN", "ERROR", "auth-gw", "ok=1", '"quoted"', "slash\\path", "200", "line\tval", ""]
    cases: List[bytes] = []
    for idx in range(count):
        kind = idx % 5
        if kind == 0:
            # Multi-line valid kvpipe records
            num_lines = rng.randint(1, 8)
            lines = []
            for _ in range(num_lines):
                num_kv = rng.randint(1, 5)
                segs = [f"{rng.choice(keys)}={rng.choice(vals)}" for _ in range(num_kv)]
                lines.append("|".join(segs).encode("utf-8"))
            cases.append(b"\n".join(lines) + (b"\n" if idx % 2 == 0 else b""))
        elif kind == 1:
            # Mixed valid and malformed lines
            cases.append(
                b"A=1|B=2\nBROKEN_LINE\n=NOKEY\nTRAILING=1|\nC=ok=yes|D=9\n"
            )
        elif kind == 2:
            # Random binary fuzz bytes with occasional delimiters
            length = rng.randint(1, 180)
            raw = bytearray(rng.getrandbits(8) for _ in range(length))
            for pos_idx in range(0, length, max(1, rng.randint(3, 12))):
                raw[pos_idx] = rng.choice([ord("="), ord("|"), ord("\n"), ord("A"), ord("1")])
            cases.append(bytes(raw))
        elif kind == 3:
            # Duplicate keys + UTF-8 multibyte values
            cases.append(
                f"K1=v{idx}|K2=caf\u00e9|K1=override_{idx}|RAW=a==b\r\n".encode("utf-8")
            )
        else:
            # Long line stress case
            chunk = ("VAL" * rng.randint(40, 200)).encode("ascii")
            cases.append(b"ID=" + str(idx).encode("ascii") + b"|DATA=" + chunk + b"|TAIL=ok\n")
    return cases


def generate_kvpipe_v1_benchmark_payload(*, seed: int = 20261121, line_count: int = 8000) -> bytes:
    """Generate a deterministic multi-line `kvpipe.v1` structured log benchmark corpus."""
    rng = random.Random(seed)
    levels = ("INFO", "WARN", "ERROR", "DEBUG")
    services = ("auth", "billing", "ingest", "planner", "sandbox")
    lines: List[bytes] = []
    for i in range(line_count):
        lvl = levels[i % len(levels)]
        svc = services[i % len(services)]
        lat = rng.randint(1, 950)
        code = 200 if lvl != "ERROR" else 500
        line = (
            f"TS=2026-11-21T19:{(i // 60) % 60:02d}:{i % 60:02d}Z"
            f"|LEVEL={lvl}|SERVICE={svc}|CODE={code}|LAT_MS={lat}|REQ=req_{i:06d}\n"
        )
        lines.append(line.encode("ascii"))
    return b"".join(lines)


@dataclass
class ForgeTaskSpec:
    """Self-contained specification and verification suite for a forgeable tool."""

    tool_id: str
    version: str
    capabilities: List[str]
    description: str
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]
    input_port: PortContract
    output_port: PortContract
    effect_contract: EffectContract
    oracle_fn: Callable[[bytes], Dict[str, Any]]
    source_code: str
    language: str = "c"
    unit_cases: List[Tuple[str, bytes]] = field(default_factory=list)
    differential_cases: List[Tuple[str, bytes]] = field(default_factory=list)
    boundary_cases: List[Tuple[str, bytes]] = field(default_factory=list)
    fuzz_cases: List[bytes] = field(default_factory=list)
    fuzz_seed: int = 20261121
    benchmark_payload: bytes = b""
    dataset_name: str = "synthetic_corpus"
    input_distribution: str = "deterministic_seeded"
    expected_reuses: Union[int, str, Decimal] = 500
    old_cost: Optional[Union[int, float, str, Decimal]] = None
    new_cost: Optional[Union[int, float, str, Decimal]] = None
    build_cost: Union[int, float, str, Decimal] = "1.0"
    verify_cost: Union[int, float, str, Decimal] = "0.5"
    maintenance_reserve: Union[int, float, str, Decimal] = "0.5"
    gap_id: Optional[str] = None
    allow_simd: bool = False
    allow_assembly: bool = False


def build_kvpipe_v1_task_spec(
    *,
    tool_id: str = "forge.kvpipe_v1_parser",
    version: str = "1.0.0",
    gap_id: Optional[str] = None,
    fuzz_seed: int = 20261121,
    fuzz_count: int = 120,
    benchmark_lines: int = 20000,
) -> ForgeTaskSpec:
    """Construct the End-to-End Demo 3 specification for `kvpipe.v1` structured log parsing."""
    unit_cases = [
        ("basic_two_lines", b"TS=2026-11-21T19:00:00Z|LEVEL=INFO|MSG=boot\nTS=2026-11-21T19:00:01Z|LEVEL=WARN|CODE=429\n"),
        ("single_pair", b"SERVICE=forge\n"),
        ("mixed_valid_malformed", b"OK=1|SVC=api\nBAD_NO_EQ\nNEXT=2\n"),
    ]
    diff_cases = [
        ("diff_multi_svc", b"A=1|Z=9|M=mid\nB=2|A=override|B=final\n"),
        ("diff_utf8_json", b'MSG="quoted\\val"|LANG=vi_\xc3\xa9|TAB=a\tb\n'),
        ("diff_crlf", b"K1=v1|K2=v2\r\n\r\nK3=v3\r\n"),
    ]
    return ForgeTaskSpec(
        tool_id=validate_tool_id(tool_id),
        version=validate_safe_text(version, field_name="version"),
        capabilities=["log.parse.kvpipe.v1", "kvpipe.v1"],
        description="Deterministic high-throughput parser for kvpipe.v1 structured logs (KEY=VAL|...).",
        input_schema={
            "type": "string",
            "format": "kvpipe.v1",
            "encoding": "utf-8",
        },
        output_schema={
            "type": "object",
            "encoding": "json",
            "ordering": "ordered",
            "required": ["format", "parsed", "malformed", "total_lines", "records"],
            "properties": {
                "format": {"type": "string"},
                "parsed": {"type": "integer"},
                "malformed": {"type": "integer"},
                "total_lines": {"type": "integer"},
                "records": {"type": "array"},
            },
        },
        input_port=PortContract(
            schema_ref="kvpipe.v1",
            semantic_type="structured_log_lines",
            encoding="utf-8",
            unit="bytes",
            cardinality="many",
            ordering="ordered",
            sensitivity="internal",
            trust_label="untrusted",
        ),
        output_port=PortContract(
            schema_ref="kvpipe.v1.parsed_records",
            semantic_type="parsed_log_records",
            encoding="json",
            unit="records",
            cardinality="many",
            ordering="ordered",
            sensitivity="internal",
            trust_label="derived",
        ),
        effect_contract=EffectContract(
            read_scopes=[],
            write_scopes=[],
            network_scopes=[],
            exec_permissions=[],
            irreversible=False,
            idempotent=True,
            resource_requirements={"max_memory_mb": 128, "timeout_seconds": 10},
        ),
        oracle_fn=parse_kvpipe_v1_python,
        source_code=_KVPIPE_V1_C99_SOURCE,
        language="c",
        unit_cases=unit_cases,
        differential_cases=diff_cases,
        boundary_cases=generate_kvpipe_v1_boundary_cases(),
        fuzz_cases=generate_kvpipe_v1_fuzz_cases(seed=fuzz_seed, count=fuzz_count),
        fuzz_seed=fuzz_seed,
        benchmark_payload=generate_kvpipe_v1_benchmark_payload(seed=fuzz_seed, line_count=benchmark_lines),
        dataset_name=f"kvpipe_v1_structured_logs_{benchmark_lines}",
        input_distribution="mixed_service_kvpipe_deterministic",
        expected_reuses=1000,
        build_cost="5.0",
        verify_cost="2.0",
        maintenance_reserve="1.0",
        gap_id=gap_id,
    )


def _reject_nonstandard_json_constant(token: str) -> Any:
    raise ValueError(f"NON_STANDARD_JSON_CONSTANT:{token}")


def _default_pure_effect_contract() -> EffectContract:
    return EffectContract(
        read_scopes=[],
        write_scopes=[],
        network_scopes=[],
        exec_permissions=[],
        irreversible=False,
        idempotent=True,
        resource_requirements={"max_memory_mb": 128, "timeout_seconds": 10},
    )


def filter_jsonl_level_python(raw_input: Union[str, bytes]) -> Dict[str, Any]:
    """Pure Python reference oracle for `jsonl_level.v1` JSONL error/critical scanner."""
    raw_bytes = raw_input if isinstance(raw_input, bytes) else str(raw_input).encode("utf-8", errors="replace")
    matches: List[Dict[str, Any]] = []
    level_counts: Dict[str, int] = {"CRITICAL": 0, "ERROR": 0}
    total_lines = 0
    malformed = 0

    pos = 0
    total_len = len(raw_bytes)
    line_num = 0
    while pos < total_len:
        line_start = pos
        nl = raw_bytes.find(b"\n", pos)
        if nl == -1:
            line = raw_bytes[pos:total_len]
            pos = total_len
        else:
            line = raw_bytes[pos:nl]
            pos = nl + 1
        line_num += 1
        if line.endswith(b"\r"):
            line = line[:-1]
        if not line:
            continue

        total_lines += 1
        try:
            text = line.decode("utf-8", errors="strict")
            obj = json.loads(text, parse_constant=_reject_nonstandard_json_constant)
        except (UnicodeDecodeError, ValueError, RecursionError):
            malformed += 1
            continue

        if not isinstance(obj, dict):
            malformed += 1
            continue

        raw_level = obj.get("level")
        if isinstance(raw_level, str):
            norm_level = raw_level.upper()
            if norm_level in ("ERROR", "CRITICAL"):
                level_counts[norm_level] += 1
                matches.append({"line": line_num, "offset": line_start, "level": norm_level})

    return {
        "format": "jsonl_level.v1",
        "total_lines": total_lines,
        "matched": len(matches),
        "malformed": malformed,
        "level_counts": level_counts,
        "matches": matches,
    }


_JSONL_LEVEL_FILTER_C99_SOURCE = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT_BYTES (64u * 1024u * 1024u)
#define MAX_JSON_DEPTH 256

typedef struct {
    size_t line_num;
    size_t offset;
    int kind; /* 1 = ERROR, 2 = CRITICAL */
} JsonlMatch;

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t pos;
} JsonCursor;

static uint8_t *read_all_stream(FILE *in_fp, size_t *out_len) {
    size_t cap = 4096u;
    size_t len = 0u;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) return NULL;
    for (;;) {
        if (len == cap) {
            if (cap >= MAX_INPUT_BYTES) {
                free(buf);
                return NULL;
            }
            size_t next_cap = cap * 2u;
            if (next_cap > MAX_INPUT_BYTES) next_cap = MAX_INPUT_BYTES;
            uint8_t *nb = (uint8_t *)realloc(buf, next_cap);
            if (!nb) {
                free(buf);
                return NULL;
            }
            buf = nb;
            cap = next_cap;
        }
        size_t got = fread(buf + len, 1u, cap - len, in_fp);
        len += got;
        if (got == 0u) {
            if (ferror(in_fp)) {
                free(buf);
                return NULL;
            }
            break;
        }
    }
    *out_len = len;
    return buf;
}

static int is_valid_utf8(const uint8_t *s, size_t n) {
    size_t i = 0u;
    while (i < n) {
        uint8_t b0 = s[i];
        if (b0 < 0x80u) {
            i += 1u;
            continue;
        }
        if (b0 >= 0xC2u && b0 <= 0xDFu) {
            if (i + 1u >= n || (s[i + 1u] & 0xC0u) != 0x80u) return 0;
            i += 2u;
            continue;
        }
        if (b0 >= 0xE0u && b0 <= 0xEFu) {
            if (i + 2u >= n) return 0;
            uint8_t b1 = s[i + 1u];
            if (b0 == 0xE0u) {
                if (b1 < 0xA0u || b1 > 0xBFu) return 0;
            } else if (b0 == 0xEDu) {
                if (b1 < 0x80u || b1 > 0x9Fu) return 0;
            } else {
                if ((b1 & 0xC0u) != 0x80u) return 0;
            }
            if ((s[i + 2u] & 0xC0u) != 0x80u) return 0;
            i += 3u;
            continue;
        }
        if (b0 >= 0xF0u && b0 <= 0xF4u) {
            if (i + 3u >= n) return 0;
            uint8_t b1 = s[i + 1u];
            if (b0 == 0xF0u) {
                if (b1 < 0x90u || b1 > 0xBFu) return 0;
            } else if (b0 == 0xF4u) {
                if (b1 < 0x80u || b1 > 0x8Fu) return 0;
            } else {
                if ((b1 & 0xC0u) != 0x80u) return 0;
            }
            if ((s[i + 2u] & 0xC0u) != 0x80u || (s[i + 3u] & 0xC0u) != 0x80u) return 0;
            i += 4u;
            continue;
        }
        return 0;
    }
    return 1;
}

static void skip_ws(JsonCursor *c) {
    while (c->pos < c->len) {
        uint8_t ch = c->buf[c->pos];
        if (ch == (uint8_t)' ' || ch == (uint8_t)'\t' || ch == (uint8_t)'\n' || ch == (uint8_t)'\r') {
            c->pos += 1u;
        } else {
            break;
        }
    }
}

static int parse_hex4(const uint8_t *p, uint32_t *out_cp) {
    uint32_t v = 0u;
    for (size_t i = 0u; i < 4u; i++) {
        uint8_t ch = p[i];
        v <<= 4u;
        if (ch >= (uint8_t)'0' && ch <= (uint8_t)'9') {
            v |= (uint32_t)(ch - (uint8_t)'0');
        } else if (ch >= (uint8_t)'a' && ch <= (uint8_t)'f') {
            v |= (uint32_t)(10u + (ch - (uint8_t)'a'));
        } else if (ch >= (uint8_t)'A' && ch <= (uint8_t)'F') {
            v |= (uint32_t)(10u + (ch - (uint8_t)'A'));
        } else {
            return 0;
        }
    }
    *out_cp = v;
    return 1;
}

static int ascii_ieq(const uint8_t *a, size_t n, const char *lit, size_t lit_len) {
    if (n != lit_len) return 0;
    for (size_t i = 0u; i < n; i++) {
        uint8_t ca = a[i];
        uint8_t cb = (uint8_t)lit[i];
        if (ca >= (uint8_t)'a' && ca <= (uint8_t)'z') ca = (uint8_t)(ca - 32u);
        if (cb >= (uint8_t)'a' && cb <= (uint8_t)'z') cb = (uint8_t)(cb - 32u);
        if (ca != cb) return 0;
    }
    return 1;
}

static int parse_json_string(JsonCursor *c, int *out_is_level_key, int *out_level_kind) {
    if (c->pos >= c->len || c->buf[c->pos] != (uint8_t)'"') return 0;
    c->pos += 1u;
    uint8_t small_buf[16];
    size_t small_len = 0u;
    int can_match = (out_is_level_key != NULL || out_level_kind != NULL);
    int match_overflow = 0;

    while (c->pos < c->len) {
        uint8_t ch = c->buf[c->pos];
        if (ch == (uint8_t)'"') {
            c->pos += 1u;
            if (out_is_level_key) {
                *out_is_level_key = (!match_overflow && small_len == 5u && memcmp(small_buf, "level", 5u) == 0) ? 1 : 0;
            }
            if (out_level_kind) {
                if (!match_overflow && ascii_ieq(small_buf, small_len, "ERROR", 5u)) {
                    *out_level_kind = 1;
                } else if (!match_overflow && ascii_ieq(small_buf, small_len, "CRITICAL", 8u)) {
                    *out_level_kind = 2;
                } else {
                    *out_level_kind = 0;
                }
            }
            return 1;
        }
        if (ch < 0x20u) return 0;
        if (ch != (uint8_t)'\\') {
            if (can_match && !match_overflow) {
                if (small_len < sizeof(small_buf)) {
                    small_buf[small_len++] = ch;
                } else {
                    match_overflow = 1;
                }
            }
            c->pos += 1u;
            continue;
        }
        c->pos += 1u;
        if (c->pos >= c->len) return 0;
        uint8_t esc = c->buf[c->pos];
        c->pos += 1u;
        uint8_t decoded = 0u;
        int is_ascii_byte = 1;
        if (esc == (uint8_t)'"' || esc == (uint8_t)'\\' || esc == (uint8_t)'/') {
            decoded = esc;
        } else if (esc == (uint8_t)'b') {
            decoded = (uint8_t)'\b';
        } else if (esc == (uint8_t)'f') {
            decoded = (uint8_t)'\f';
        } else if (esc == (uint8_t)'n') {
            decoded = (uint8_t)'\n';
        } else if (esc == (uint8_t)'r') {
            decoded = (uint8_t)'\r';
        } else if (esc == (uint8_t)'t') {
            decoded = (uint8_t)'\t';
        } else if (esc == (uint8_t)'u') {
            uint32_t cp = 0u;
            if (c->pos + 4u > c->len || !parse_hex4(c->buf + c->pos, &cp)) return 0;
            c->pos += 4u;
            if (cp <= 0x7Fu) {
                decoded = (uint8_t)cp;
            } else {
                is_ascii_byte = 0;
            }
        } else {
            return 0;
        }
        if (can_match && !match_overflow) {
            if (is_ascii_byte && small_len < sizeof(small_buf)) {
                small_buf[small_len++] = decoded;
            } else {
                match_overflow = 1;
            }
        }
    }
    return 0;
}

static int parse_json_number(JsonCursor *c) {
    if (c->pos < c->len && c->buf[c->pos] == (uint8_t)'-') {
        c->pos += 1u;
    }
    if (c->pos >= c->len) return 0;
    size_t int_digits = 0u;
    if (c->buf[c->pos] == (uint8_t)'0') {
        c->pos += 1u;
        int_digits = 1u;
    } else if (c->buf[c->pos] >= (uint8_t)'1' && c->buf[c->pos] <= (uint8_t)'9') {
        while (c->pos < c->len && c->buf[c->pos] >= (uint8_t)'0' && c->buf[c->pos] <= (uint8_t)'9') {
            c->pos += 1u;
            int_digits += 1u;
        }
    } else {
        return 0;
    }
    int has_frac = 0;
    if (c->pos < c->len && c->buf[c->pos] == (uint8_t)'.') {
        has_frac = 1;
        c->pos += 1u;
        if (c->pos >= c->len || c->buf[c->pos] < (uint8_t)'0' || c->buf[c->pos] > (uint8_t)'9') return 0;
        while (c->pos < c->len && c->buf[c->pos] >= (uint8_t)'0' && c->buf[c->pos] <= (uint8_t)'9') {
            c->pos += 1u;
        }
    }
    int has_exp = 0;
    if (c->pos < c->len && (c->buf[c->pos] == (uint8_t)'e' || c->buf[c->pos] == (uint8_t)'E')) {
        has_exp = 1;
        c->pos += 1u;
        if (c->pos < c->len && (c->buf[c->pos] == (uint8_t)'+' || c->buf[c->pos] == (uint8_t)'-')) {
            c->pos += 1u;
        }
        if (c->pos >= c->len || c->buf[c->pos] < (uint8_t)'0' || c->buf[c->pos] > (uint8_t)'9') return 0;
        while (c->pos < c->len && c->buf[c->pos] >= (uint8_t)'0' && c->buf[c->pos] <= (uint8_t)'9') {
            c->pos += 1u;
        }
    }
    if (!has_frac && !has_exp && int_digits > 4300u) {
        return 0;
    }
    return 1;
}

static int parse_json_value(JsonCursor *c, int depth);

static int parse_json_array(JsonCursor *c, int depth) {
    if (depth > MAX_JSON_DEPTH || c->pos >= c->len || c->buf[c->pos] != (uint8_t)'[') return 0;
    c->pos += 1u;
    skip_ws(c);
    if (c->pos < c->len && c->buf[c->pos] == (uint8_t)']') {
        c->pos += 1u;
        return 1;
    }
    for (;;) {
        if (!parse_json_value(c, depth + 1)) return 0;
        skip_ws(c);
        if (c->pos >= c->len) return 0;
        if (c->buf[c->pos] == (uint8_t)',') {
            c->pos += 1u;
            continue;
        }
        if (c->buf[c->pos] == (uint8_t)']') {
            c->pos += 1u;
            return 1;
        }
        return 0;
    }
}

static int parse_json_object(JsonCursor *c, int depth, int *top_level_kind) {
    if (depth > MAX_JSON_DEPTH || c->pos >= c->len || c->buf[c->pos] != (uint8_t)'{') return 0;
    c->pos += 1u;
    skip_ws(c);
    if (c->pos < c->len && c->buf[c->pos] == (uint8_t)'}') {
        c->pos += 1u;
        return 1;
    }
    for (;;) {
        skip_ws(c);
        int is_level_key = 0;
        if (!parse_json_string(c, (depth == 0) ? &is_level_key : NULL, NULL)) return 0;
        skip_ws(c);
        if (c->pos >= c->len || c->buf[c->pos] != (uint8_t)':') return 0;
        c->pos += 1u;
        skip_ws(c);
        if (depth == 0 && is_level_key && top_level_kind != NULL) {
            if (c->pos < c->len && c->buf[c->pos] == (uint8_t)'"') {
                int val_kind = 0;
                if (!parse_json_string(c, NULL, &val_kind)) return 0;
                *top_level_kind = val_kind;
            } else {
                if (!parse_json_value(c, depth + 1)) return 0;
                *top_level_kind = 0;
            }
        } else {
            if (!parse_json_value(c, depth + 1)) return 0;
        }
        skip_ws(c);
        if (c->pos >= c->len) return 0;
        if (c->buf[c->pos] == (uint8_t)',') {
            c->pos += 1u;
            continue;
        }
        if (c->buf[c->pos] == (uint8_t)'}') {
            c->pos += 1u;
            return 1;
        }
        return 0;
    }
}

static int parse_json_value(JsonCursor *c, int depth) {
    if (depth > MAX_JSON_DEPTH) return 0;
    skip_ws(c);
    if (c->pos >= c->len) return 0;
    uint8_t ch = c->buf[c->pos];
    if (ch == (uint8_t)'"') return parse_json_string(c, NULL, NULL);
    if (ch == (uint8_t)'{') return parse_json_object(c, depth + 1, NULL);
    if (ch == (uint8_t)'[') return parse_json_array(c, depth + 1);
    if (ch == (uint8_t)'t') {
        if (c->pos + 4u <= c->len && memcmp(c->buf + c->pos, "true", 4u) == 0) {
            c->pos += 4u;
            return 1;
        }
        return 0;
    }
    if (ch == (uint8_t)'f') {
        if (c->pos + 5u <= c->len && memcmp(c->buf + c->pos, "false", 5u) == 0) {
            c->pos += 5u;
            return 1;
        }
        return 0;
    }
    if (ch == (uint8_t)'n') {
        if (c->pos + 4u <= c->len && memcmp(c->buf + c->pos, "null", 4u) == 0) {
            c->pos += 4u;
            return 1;
        }
        return 0;
    }
    if (ch == (uint8_t)'-' || (ch >= (uint8_t)'0' && ch <= (uint8_t)'9')) {
        return parse_json_number(c);
    }
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOFBF, 65536u);
    FILE *in_fp = stdin;
    if (argc > 1 && argv[1] && argv[1][0] != '\0') {
        in_fp = fopen(argv[1], "rb");
        if (!in_fp) {
            fprintf(stderr, "OPEN_FAILED\n");
            return 2;
        }
    }

    size_t total_len = 0u;
    uint8_t *buf = read_all_stream(in_fp, &total_len);
    if (in_fp != stdin) {
        fclose(in_fp);
    }
    if (!buf) {
        fprintf(stderr, "READ_FAILED\n");
        return 3;
    }

    size_t cap = 64u;
    size_t count = 0u;
    JsonlMatch *matches = (JsonlMatch *)malloc(cap * sizeof(JsonlMatch));
    if (!matches) {
        free(buf);
        return 4;
    }

    size_t total_lines = 0u;
    size_t malformed = 0u;
    size_t error_count = 0u;
    size_t critical_count = 0u;
    size_t line_num = 0u;
    size_t pos = 0u;

    while (pos < total_len) {
        size_t line_start = pos;
        const uint8_t *nl_ptr = (const uint8_t *)memchr(buf + pos, '\n', total_len - pos);
        size_t end = nl_ptr ? (size_t)(nl_ptr - buf) : total_len;
        size_t next_pos = nl_ptr ? (end + 1u) : total_len;
        line_num += 1u;
        size_t line_end = end;
        if (line_end > pos && buf[line_end - 1u] == (uint8_t)'\r') {
            line_end -= 1u;
        }
        size_t line_len = line_end - pos;
        if (line_len == 0u) {
            pos = next_pos;
            continue;
        }
        total_lines += 1u;
        const uint8_t *line_ptr = buf + pos;
        int level_kind = 0;
        int valid = is_valid_utf8(line_ptr, line_len);
        if (valid) {
            JsonCursor cur = {line_ptr, line_len, 0u};
            skip_ws(&cur);
            if (!parse_json_object(&cur, 0, &level_kind)) {
                valid = 0;
            } else {
                skip_ws(&cur);
                if (cur.pos != cur.len) {
                    valid = 0;
                }
            }
        }
        if (!valid) {
            malformed += 1u;
        } else if (level_kind != 0) {
            if (count == cap) {
                if (cap > SIZE_MAX / 2u / sizeof(JsonlMatch)) {
                    free(matches);
                    free(buf);
                    return 5;
                }
                size_t next_cap = cap * 2u;
                JsonlMatch *nm = (JsonlMatch *)realloc(matches, next_cap * sizeof(JsonlMatch));
                if (!nm) {
                    free(matches);
                    free(buf);
                    return 6;
                }
                matches = nm;
                cap = next_cap;
            }
            matches[count].line_num = line_num;
            matches[count].offset = line_start;
            matches[count].kind = level_kind;
            count += 1u;
            if (level_kind == 1) {
                error_count += 1u;
            } else {
                critical_count += 1u;
            }
        }
        pos = next_pos;
    }

    printf(
        "{\"format\":\"jsonl_level.v1\",\"total_lines\":%zu,\"matched\":%zu,\"malformed\":%zu,"
        "\"level_counts\":{\"CRITICAL\":%zu,\"ERROR\":%zu},\"matches\":[",
        total_lines,
        count,
        malformed,
        critical_count,
        error_count
    );
    for (size_t i = 0u; i < count; i++) {
        if (i > 0u) fputc(',', stdout);
        printf(
            "{\"line\":%zu,\"offset\":%zu,\"level\":\"%s\"}",
            matches[i].line_num,
            matches[i].offset,
            (matches[i].kind == 2) ? "CRITICAL" : "ERROR"
        );
    }
    fputs("]}\n", stdout);

    free(matches);
    free(buf);
    return 0;
}
"""


def generate_jsonl_level_filter_boundary_cases() -> List[Tuple[str, bytes]]:
    """Return boundary test vectors for `jsonl_level.v1` scanner."""
    huge_msg = b"A" * 70000
    return [
        ("empty", b""),
        ("single_newline", b"\n"),
        ("spaces_only_line", b"   \n"),
        ("non_object_array", b"[1, 2, 3]\n"),
        ("non_object_string", b'"ERROR"\n'),
        ("malformed_trailing_comma", b'{"level":"ERROR",}\n'),
        ("malformed_single_quotes", b"{'level':'ERROR'}\n"),
        ("nan_constant_rejected", b'{"level":"ERROR","x":NaN}\n'),
        ("duplicate_level_last_wins", b'{"level":"ERROR","level":"INFO"}\n{"level":"INFO","level":"CRITICAL"}\n'),
        ("nested_level_ignored", b'{"meta":{"level":"ERROR"},"level":"INFO"}\n'),
        ("unicode_escape_level", b'{"\\u006cevel":"\\u0045RROR"}\n'),
        ("case_insensitive_level", b'{"level":"error"}\r\n\r\n{"level":"CrItIcAl"}\r\n'),
        ("huge_line_70kb", b'{"level":"CRITICAL","blob":"' + huge_msg + b'"}\n'),
        ("embedded_nul_and_invalid_utf8", b'{"level":"ERROR\x00"}\n{"level":"ERROR","raw":"\xff\xfe"}\n'),
    ]


def generate_jsonl_level_filter_fuzz_cases(*, seed: int = 20261122, count: int = 120) -> List[bytes]:
    """Generate `count` deterministic seeded fuzz byte payloads for `jsonl_level.v1`."""
    rng = random.Random(seed)
    levels = ["DEBUG", "INFO", "WARN", "ERROR", "CRITICAL", "error", "critical", "fatal"]
    services = ["auth", "billing", "sandbox", "forge", "planner"]
    cases: List[bytes] = []
    for idx in range(count):
        kind = idx % 5
        if kind == 0:
            lines = []
            for j in range(rng.randint(1, 10)):
                lvl = rng.choice(levels)
                svc = rng.choice(services)
                lines.append(
                    json.dumps({"ts": j, "level": lvl, "service": svc, "ok": lvl not in ("ERROR", "CRITICAL")}).encode(
                        "utf-8"
                    )
                )
            cases.append(b"\n".join(lines) + (b"\n" if idx % 2 == 0 else b""))
        elif kind == 1:
            cases.append(
                b'{"level":"ERROR","msg":"ok"}\n'
                b'{"broken":\n'
                b'{"level": 500}\n'
                b'{"nested":{"level":"CRITICAL"}}\n'
                b'{"level":"CRITICAL","dup":1}\n'
            )
        elif kind == 2:
            length = rng.randint(1, 180)
            raw = bytearray(rng.getrandbits(8) for _ in range(length))
            for pos_idx in range(0, length, max(1, rng.randint(3, 10))):
                raw[pos_idx] = rng.choice([ord("{"), ord("}"), ord('"'), ord(":"), ord(","), ord("\n")])
            cases.append(bytes(raw))
        elif kind == 3:
            cases.append(
                f'  {{"level": "ERROR", "k": "caf\\u00e9_{idx}", "arr": [1, true, null, -2.5e1]}}  \r\n'.encode("utf-8")
            )
        else:
            pad = ("Z" * rng.randint(50, 200))
            cases.append(
                f'{{"id":{idx},"level":"CRITICAL","pad":"{pad}"}}\n{{"id":{idx + 1},"level":"INFO"}}\n'.encode("utf-8")
            )
    return cases


def generate_jsonl_level_filter_benchmark_payload(*, seed: int = 20261122, line_count: int = 20000) -> bytes:
    """Generate a deterministic multi-line JSONL benchmark corpus."""
    rng = random.Random(seed)
    levels = ("INFO", "WARN", "ERROR", "DEBUG", "CRITICAL", "INFO", "WARN", "INFO")
    services = ("auth", "billing", "ingest", "planner", "sandbox")
    lines: List[bytes] = []
    for i in range(line_count):
        lvl = levels[i % len(levels)]
        svc = services[i % len(services)]
        lat = rng.randint(1, 950)
        lines.append(
            f'{{"seq":{i},"level":"{lvl}","service":"{svc}","lat_ms":{lat},"ok":true}}\n'.encode("ascii")
        )
    return b"".join(lines)


def build_jsonl_level_filter_task_spec(
    *,
    tool_id: str = "forge.jsonl_level_filter",
    version: str = "1.0.0",
    gap_id: Optional[str] = None,
    fuzz_seed: int = 20261122,
    fuzz_count: int = 120,
    benchmark_lines: int = 20000,
) -> ForgeTaskSpec:
    """Construct the specification for streaming C99 JSONL error/critical event scanner."""
    unit_cases = [
        (
            "basic_mixed_levels",
            b'{"ts":1,"level":"INFO"}\n{"ts":2,"level":"ERROR"}\n{"ts":3,"level":"CRITICAL"}\n',
        ),
        ("single_error", b'{"level":"error","msg":"timeout"}\n'),
        ("mixed_valid_malformed", b'{"level":"CRITICAL"}\nBAD_JSON\n{"level":"WARN"}\n'),
    ]
    diff_cases = [
        ("diff_crlf_and_blanks", b'{"level":"ERROR"}\r\n\r\n{"level":"INFO"}\r\n{"level":"CRITICAL"}\r\n'),
        ("diff_nested_and_dup", b'{"a":{"level":"ERROR"},"level":"INFO"}\n{"level":"ERROR","level":"CRITICAL"}\n'),
        ("diff_escapes", b'{"msg":"line\\n\\t\\"ok\\"","\\u006cevel":"\\u0045RROR"}\n'),
    ]
    return ForgeTaskSpec(
        tool_id=validate_tool_id(tool_id),
        version=validate_safe_text(version, field_name="version"),
        capabilities=["log.filter.jsonl_level.v1", "jsonl.filter"],
        description="Deterministic streaming C99 JSONL scanner filtering ERROR and CRITICAL events.",
        input_schema={"type": "string", "format": "jsonl", "encoding": "utf-8"},
        output_schema={
            "type": "object",
            "encoding": "json",
            "ordering": "ordered",
            "required": ["format", "total_lines", "matched", "malformed", "level_counts", "matches"],
            "properties": {
                "format": {"type": "string"},
                "total_lines": {"type": "integer"},
                "matched": {"type": "integer"},
                "malformed": {"type": "integer"},
                "level_counts": {"type": "object"},
                "matches": {"type": "array"},
            },
        },
        input_port=PortContract(
            schema_ref="jsonl.log_lines",
            semantic_type="structured_log_lines",
            encoding="utf-8",
            unit="bytes",
            cardinality="many",
            ordering="ordered",
            sensitivity="internal",
            trust_label="untrusted",
        ),
        output_port=PortContract(
            schema_ref="jsonl_level.v1.summary",
            semantic_type="filtered_log_events",
            encoding="json",
            unit="records",
            cardinality="many",
            ordering="ordered",
            sensitivity="internal",
            trust_label="derived",
        ),
        effect_contract=_default_pure_effect_contract(),
        oracle_fn=filter_jsonl_level_python,
        source_code=_JSONL_LEVEL_FILTER_C99_SOURCE,
        language="c",
        unit_cases=unit_cases,
        differential_cases=diff_cases,
        boundary_cases=generate_jsonl_level_filter_boundary_cases(),
        fuzz_cases=generate_jsonl_level_filter_fuzz_cases(seed=fuzz_seed, count=fuzz_count),
        fuzz_seed=fuzz_seed,
        benchmark_payload=generate_jsonl_level_filter_benchmark_payload(seed=fuzz_seed, line_count=benchmark_lines),
        dataset_name=f"jsonl_level_v1_logs_{benchmark_lines}",
        input_distribution="mixed_service_jsonl_deterministic",
        expected_reuses=1000,
        build_cost="5.0",
        verify_cost="2.0",
        maintenance_reserve="1.0",
        gap_id=gap_id,
    )


_INT64_MIN = -(1 << 63)
_INT64_MAX = (1 << 63) - 1
_CSV_INT_RE = re.compile(rb"^[+-]?[0-9]+$")


def sum_csv_python(raw_input: Union[str, bytes]) -> Dict[str, Any]:
    """Pure Python reference oracle for `csv_sum.v1` checked int64 CSV aggregator."""
    raw_bytes = raw_input if isinstance(raw_input, bytes) else str(raw_input).encode("utf-8", errors="replace")
    rows = 0
    malformed = 0
    total_sum = 0
    overflow = False

    pos = 0
    total_len = len(raw_bytes)
    while pos < total_len:
        nl = raw_bytes.find(b"\n", pos)
        if nl == -1:
            line = raw_bytes[pos:total_len]
            pos = total_len
        else:
            line = raw_bytes[pos:nl]
            pos = nl + 1
        if line.endswith(b"\r"):
            line = line[:-1]
        if not line:
            continue

        cells = line.split(b",")
        parsed_vals: List[int] = []
        row_malformed = False
        row_overflow = False
        for cell in cells:
            trimmed = cell.strip(b" \t")
            if not _CSV_INT_RE.fullmatch(trimmed):
                row_malformed = True
                break
            mag_digits = trimmed.lstrip(b"+-").lstrip(b"0")
            if len(mag_digits) > 19:
                row_overflow = True
                continue
            val = int(trimmed)
            if val < _INT64_MIN or val > _INT64_MAX:
                row_overflow = True
            else:
                parsed_vals.append(val)

        if row_malformed:
            malformed += 1
            continue
        if row_overflow:
            overflow = True
            break

        cand_sum = total_sum
        for val in parsed_vals:
            cand_sum += val
            if cand_sum < _INT64_MIN or cand_sum > _INT64_MAX:
                overflow = True
                break
        if overflow:
            break
        total_sum = cand_sum
        rows += 1

    return {
        "format": "csv_sum.v1",
        "rows": rows,
        "sum": total_sum,
        "malformed": malformed,
        "overflow": overflow,
        "status": "OVERFLOW" if overflow else "OK",
    }


_CSV_SUM_C99_SOURCE = r"""
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT_BYTES (64u * 1024u * 1024u)

static uint8_t *read_all_stream(FILE *in_fp, size_t *out_len) {
    size_t cap = 4096u;
    size_t len = 0u;
    uint8_t *buf = (uint8_t *)malloc(cap);
    if (!buf) return NULL;
    for (;;) {
        if (len == cap) {
            if (cap >= MAX_INPUT_BYTES) {
                free(buf);
                return NULL;
            }
            size_t next_cap = cap * 2u;
            if (next_cap > MAX_INPUT_BYTES) next_cap = MAX_INPUT_BYTES;
            uint8_t *nb = (uint8_t *)realloc(buf, next_cap);
            if (!nb) {
                free(buf);
                return NULL;
            }
            buf = nb;
            cap = next_cap;
        }
        size_t got = fread(buf + len, 1u, cap - len, in_fp);
        len += got;
        if (got == 0u) {
            if (ferror(in_fp)) {
                free(buf);
                return NULL;
            }
            break;
        }
    }
    *out_len = len;
    return buf;
}

static int parse_checked_i64(const uint8_t *cell, size_t len, int64_t *out_val) {
    size_t start = 0u;
    size_t end = len;
    while (start < end && (cell[start] == (uint8_t)' ' || cell[start] == (uint8_t)'\t')) {
        start += 1u;
    }
    while (end > start && (cell[end - 1u] == (uint8_t)' ' || cell[end - 1u] == (uint8_t)'\t')) {
        end -= 1u;
    }
    if (start >= end) return 1;

    int neg = 0;
    size_t idx = start;
    if (cell[idx] == (uint8_t)'-') {
        neg = 1;
        idx += 1u;
    } else if (cell[idx] == (uint8_t)'+') {
        idx += 1u;
    }
    if (idx >= end) return 1;

    for (size_t k = idx; k < end; k++) {
        if (cell[k] < (uint8_t)'0' || cell[k] > (uint8_t)'9') {
            return 1;
        }
    }

    uint64_t limit = neg ? ((uint64_t)INT64_MAX + 1ULL) : (uint64_t)INT64_MAX;
    uint64_t mag = 0ULL;
    for (size_t k = idx; k < end; k++) {
        uint64_t d = (uint64_t)(cell[k] - (uint8_t)'0');
        if (mag > (limit - d) / 10ULL) {
            return 2;
        }
        mag = mag * 10ULL + d;
    }
    if (neg) {
        if (mag == (uint64_t)INT64_MAX + 1ULL) {
            *out_val = INT64_MIN;
        } else {
            *out_val = -(int64_t)mag;
        }
    } else {
        *out_val = (int64_t)mag;
    }
    return 0;
}

static int checked_add_i64(int64_t a, int64_t b, int64_t *out) {
    if (b > 0 && a > INT64_MAX - b) return 0;
    if (b < 0 && a < INT64_MIN - b) return 0;
    *out = a + b;
    return 1;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOFBF, 65536u);
    FILE *in_fp = stdin;
    if (argc > 1 && argv[1] && argv[1][0] != '\0') {
        in_fp = fopen(argv[1], "rb");
        if (!in_fp) {
            fprintf(stderr, "OPEN_FAILED\n");
            return 2;
        }
    }

    size_t total_len = 0u;
    uint8_t *buf = read_all_stream(in_fp, &total_len);
    if (in_fp != stdin) {
        fclose(in_fp);
    }
    if (!buf) {
        fprintf(stderr, "READ_FAILED\n");
        return 3;
    }

    size_t row_cap = 32u;
    int64_t *row_vals = (int64_t *)malloc(row_cap * sizeof(int64_t));
    if (!row_vals) {
        free(buf);
        return 4;
    }

    size_t rows = 0u;
    size_t malformed = 0u;
    int64_t total_sum = 0;
    int overflow = 0;
    size_t pos = 0u;

    while (pos < total_len) {
        const uint8_t *nl_ptr = (const uint8_t *)memchr(buf + pos, '\n', total_len - pos);
        size_t end = nl_ptr ? (size_t)(nl_ptr - buf) : total_len;
        size_t next_pos = nl_ptr ? (end + 1u) : total_len;
        size_t line_end = end;
        if (line_end > pos && buf[line_end - 1u] == (uint8_t)'\r') {
            line_end -= 1u;
        }
        size_t line_len = line_end - pos;
        if (line_len == 0u) {
            pos = next_pos;
            continue;
        }

        const uint8_t *line = buf + pos;
        size_t cell_count = 0u;
        int row_malformed = 0;
        int row_parse_overflow = 0;
        size_t seg_start = 0u;

        for (size_t idx = 0u; idx <= line_len; idx++) {
            if (idx < line_len && line[idx] != (uint8_t)',') {
                continue;
            }
            int64_t val = 0;
            int rc = parse_checked_i64(line + seg_start, idx - seg_start, &val);
            if (rc == 1) {
                row_malformed = 1;
                break;
            }
            if (rc == 2) {
                row_parse_overflow = 1;
            } else {
                if (cell_count == row_cap) {
                    if (row_cap > SIZE_MAX / 2u / sizeof(int64_t)) {
                        free(row_vals);
                        free(buf);
                        return 5;
                    }
                    size_t next_cap = row_cap * 2u;
                    int64_t *nr = (int64_t *)realloc(row_vals, next_cap * sizeof(int64_t));
                    if (!nr) {
                        free(row_vals);
                        free(buf);
                        return 6;
                    }
                    row_vals = nr;
                    row_cap = next_cap;
                }
                row_vals[cell_count++] = val;
            }
            seg_start = idx + 1u;
        }

        if (row_malformed) {
            malformed += 1u;
            pos = next_pos;
            continue;
        }
        if (row_parse_overflow) {
            overflow = 1;
            break;
        }

        int64_t cand_sum = total_sum;
        for (size_t j = 0u; j < cell_count; j++) {
            if (!checked_add_i64(cand_sum, row_vals[j], &cand_sum)) {
                overflow = 1;
                break;
            }
        }
        if (overflow) {
            break;
        }
        total_sum = cand_sum;
        rows += 1u;
        pos = next_pos;
    }

    printf(
        "{\"format\":\"csv_sum.v1\",\"rows\":%zu,\"sum\":%" PRId64 ",\"malformed\":%zu,\"overflow\":%s,\"status\":\"%s\"}\n",
        rows,
        total_sum,
        malformed,
        overflow ? "true" : "false",
        overflow ? "OVERFLOW" : "OK"
    );

    free(row_vals);
    free(buf);
    return 0;
}
"""


def generate_csv_sum_boundary_cases() -> List[Tuple[str, bytes]]:
    """Return boundary test vectors for `csv_sum.v1`, including int64 overflow edges."""
    wide_row = b",".join([b"1"] * 400) + b"\n"
    return [
        ("empty", b""),
        ("single_newline", b"\n"),
        ("crlf_and_blanks", b"10, 20 \r\n\r\n-5, +15\r\n"),
        ("int64_max_exact", b"9223372036854775807\n-9223372036854775807\n42\n"),
        ("int64_min_exact", b"-9223372036854775808\n9223372036854775807\n"),
        ("add_overflow_positive", b"9223372036854775807\n1\n5\n"),
        ("add_overflow_negative", b"-9223372036854775808\n-1\n"),
        ("parse_overflow_positive", b"10\n9223372036854775808\n20\n"),
        ("parse_overflow_negative", b"-9223372036854775809\n"),
        ("huge_digit_count_overflow", b"0000" + (b"9" * 4500) + b"\n"),
        ("malformed_empty_cell", b"1,,2\n10,\n,20\n"),
        ("malformed_overrides_parse_overflow", b"9223372036854775808,not_int\n10,20\n"),
        ("wide_row_400_cols", wide_row),
        ("embedded_nul_and_spaces", b"1,2\x003\n   \n4,5\n"),
    ]


def generate_csv_sum_fuzz_cases(*, seed: int = 20261123, count: int = 120) -> List[bytes]:
    """Generate `count` deterministic seeded fuzz byte payloads for `csv_sum.v1`."""
    rng = random.Random(seed)
    cases: List[bytes] = []
    for idx in range(count):
        kind = idx % 5
        if kind == 0:
            lines = []
            for _ in range(rng.randint(1, 10)):
                cols = [str(rng.randint(-100000, 100000)) for _ in range(rng.randint(1, 6))]
                lines.append(",".join(cols).encode("ascii"))
            cases.append(b"\n".join(lines) + (b"\n" if idx % 2 == 0 else b""))
        elif kind == 1:
            cases.append(b"10,20\r\nbad,row\r\n-5, 15 \r\n\r\n1,,2\r\n")
        elif kind == 2:
            length = rng.randint(1, 160)
            raw = bytearray(rng.getrandbits(8) for _ in range(length))
            for pos_idx in range(0, length, max(1, rng.randint(2, 8))):
                raw[pos_idx] = rng.choice([ord(","), ord("-"), ord("+"), ord("1"), ord("0"), ord("\n")])
            cases.append(bytes(raw))
        elif kind == 3:
            big_a = _INT64_MAX - rng.randint(0, 50)
            big_b = rng.randint(0, 100)
            cases.append(f"{big_a}\n{big_b}\n-10\n".encode("ascii"))
        else:
            vals = [str((idx * 17 + j) % 97 - 40) for j in range(60)]
            cases.append((",".join(vals) + "\n").encode("ascii"))
    return cases


def generate_csv_sum_benchmark_payload(*, seed: int = 20261123, line_count: int = 30000) -> bytes:
    """Generate a deterministic multi-column numeric CSV benchmark corpus."""
    rng = random.Random(seed)
    lines: List[bytes] = []
    for i in range(line_count):
        a = rng.randint(-5000, 5000)
        b = rng.randint(0, 10000)
        c = (i * 13) % 997
        d = rng.randint(-1000, 1000)
        e = i % 250
        f = rng.randint(1, 500)
        lines.append(f"{a},{b},{c},{d},{e},{f}\n".encode("ascii"))
    return b"".join(lines)


def build_csv_sum_task_spec(
    *,
    tool_id: str = "forge.csv_sum",
    version: str = "1.0.0",
    gap_id: Optional[str] = None,
    fuzz_seed: int = 20261123,
    fuzz_count: int = 120,
    benchmark_lines: int = 30000,
) -> ForgeTaskSpec:
    """Construct the specification for checked int64 CSV aggregator."""
    unit_cases = [
        ("basic_rows", b"10,20,30\n-5,15\n100\n"),
        ("crlf_blanks", b"1,2\r\n\r\n3,4\r\n"),
        ("mixed_malformed", b"5,5\nbad,1\n10\n"),
    ]
    diff_cases = [
        ("diff_signed_spaces", b" +10 , -3 \n 0007 , -0 \n"),
        ("diff_int64_edges", b"9223372036854775807\n-9223372036854775808\n1\n"),
        ("diff_overflow_stop", b"9223372036854775807\n1\nbad_after_overflow\n"),
    ]
    return ForgeTaskSpec(
        tool_id=validate_tool_id(tool_id),
        version=validate_safe_text(version, field_name="version"),
        capabilities=["data.csv_sum.v1", "csv.aggregate"],
        description="Deterministic C99 checked int64 aggregator for structured numeric CSV rows.",
        input_schema={"type": "string", "format": "csv", "encoding": "utf-8"},
        output_schema={
            "type": "object",
            "encoding": "json",
            "ordering": "unordered",
            "required": ["format", "rows", "sum", "malformed", "overflow", "status"],
            "properties": {
                "format": {"type": "string"},
                "rows": {"type": "integer"},
                "sum": {"type": "integer"},
                "malformed": {"type": "integer"},
                "overflow": {"type": "boolean"},
                "status": {"type": "string"},
            },
        },
        input_port=PortContract(
            schema_ref="csv.numeric_rows",
            semantic_type="numeric_table_rows",
            encoding="utf-8",
            unit="bytes",
            cardinality="many",
            ordering="ordered",
            sensitivity="internal",
            trust_label="untrusted",
        ),
        output_port=PortContract(
            schema_ref="csv_sum.v1.aggregate",
            semantic_type="aggregated_integer_sum",
            encoding="json",
            unit="count",
            cardinality="one",
            ordering="unordered",
            sensitivity="internal",
            trust_label="derived",
            precision="int64",
        ),
        effect_contract=_default_pure_effect_contract(),
        oracle_fn=sum_csv_python,
        source_code=_CSV_SUM_C99_SOURCE,
        language="c",
        unit_cases=unit_cases,
        differential_cases=diff_cases,
        boundary_cases=generate_csv_sum_boundary_cases(),
        fuzz_cases=generate_csv_sum_fuzz_cases(seed=fuzz_seed, count=fuzz_count),
        fuzz_seed=fuzz_seed,
        benchmark_payload=generate_csv_sum_benchmark_payload(seed=fuzz_seed, line_count=benchmark_lines),
        dataset_name=f"csv_sum_v1_rows_{benchmark_lines}",
        input_distribution="mixed_numeric_csv_deterministic",
        expected_reuses=1000,
        build_cost="5.0",
        verify_cost="2.0",
        maintenance_reserve="1.0",
        gap_id=gap_id,
    )


FORGE_TEMPLATE_REGISTRY: Dict[str, Callable[..., ForgeTaskSpec]] = {
    "log.parse.kvpipe.v1": build_kvpipe_v1_task_spec,
    "kvpipe.v1": build_kvpipe_v1_task_spec,
    "log.filter.jsonl_level.v1": build_jsonl_level_filter_task_spec,
    "jsonl.filter": build_jsonl_level_filter_task_spec,
    "data.csv_sum.v1": build_csv_sum_task_spec,
    "csv.aggregate": build_csv_sum_task_spec,
}


@dataclass
class ForgeResult:
    """Structured result emitted by `NativeToolForge.forge(...)`."""

    verified: bool
    execution_status: ExecutionStatus
    build: ToolBuild
    tool_spec: Optional[ToolSpec]
    escalation: EscalationDecision
    benchmark_report: Optional[BenchmarkReport] = None
    sandbox_receipt: Optional[SandboxReceipt] = None
    manifest_path: Optional[Path] = None
    binary_path: Optional[Path] = None
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return redact_secrets_in_value(
            {
                "verified": self.verified,
                "execution_status": self.execution_status.value,
                "build": self.build.to_dict(),
                "tool_spec": self.tool_spec.to_dict() if self.tool_spec else None,
                "escalation": self.escalation.to_dict(),
                "benchmark_report": self.benchmark_report.to_dict() if self.benchmark_report else None,
                "sandbox_receipt": self.sandbox_receipt.to_dict() if self.sandbox_receipt else None,
                "manifest_path": str(self.manifest_path) if self.manifest_path else None,
                "reason": redact_secrets_in_text(self.reason),
            }
        )


def _read_binary_hash_nofollow(bin_path: Path) -> str:
    assert_not_symlink(bin_path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(bin_path), flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError(f"FORGE_BINARY_NOT_REGULAR: {bin_path}")
        chunks: List[bytes] = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return sha256_digest(b"".join(chunks))
    finally:
        os.close(fd)


class NativeToolForge:
    """Stage 3 Autonomous Native Tool Forge strictly obeying monotonic `ForgeState` & OS sandboxing."""

    def __init__(
        self,
        workspace_root: Union[str, Path],
        *,
        sandbox: Optional[ToolSandbox] = None,
        manifest_store: Optional[BuildManifestStore] = None,
        profile: Union[SecurityProfile, str] = SecurityProfile.LOCAL_RESEARCH,
    ) -> None:
        raw_ws = Path(str(workspace_root))
        assert_not_symlink(raw_ws)
        raw_ws.mkdir(parents=True, exist_ok=True)
        self.workspace_root: Path = raw_ws.resolve()
        self.profile: SecurityProfile = (
            profile if isinstance(profile, SecurityProfile) else SecurityProfile(str(profile).strip().upper())
        )

        self.sandbox: ToolSandbox = sandbox or ToolSandbox(self.workspace_root / ".kintsugi" / "sandbox_ws")
        self.manifest_store: BuildManifestStore = manifest_store or BuildManifestStore(
            workspace_root=self.workspace_root
        )
        self.forged_tools_root: Path = self.workspace_root / DEFAULT_FORGED_TOOLS_REL_DIR
        assert_not_symlink(self.forged_tools_root)
        self.forged_tools_root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.forged_tools_root, 0o700)
        self._custom_templates: Dict[str, Callable[..., ForgeTaskSpec]] = {}

    def register_template(
        self,
        capability: Union[str, Sequence[str]],
        builder: Callable[..., ForgeTaskSpec],
    ) -> None:
        """Register a capability synthesis template builder on this forge instance."""
        if not callable(builder):
            raise ValueError("INVALID_FORGE_TEMPLATE_BUILDER: expected callable.")
        caps = [capability] if isinstance(capability, str) else list(capability)
        if not caps:
            raise ValueError("INVALID_FORGE_TEMPLATE_CAPABILITIES: must provide at least one capability.")
        for cap in caps:
            cleaned = validate_safe_text(str(cap), field_name="capability")
            self._custom_templates[cleaned] = builder

    def list_templates(self) -> List[str]:
        """Return deterministically sorted capability names supported by registered templates."""
        merged = {**FORGE_TEMPLATE_REGISTRY, **self._custom_templates}
        return sorted(merged.keys())

    def evaluate_escalation_ladder(
        self,
        required_capabilities: Sequence[str],
        *,
        registry: Optional[ToolRegistry] = None,
        security_context: Optional[SecurityContext] = None,
        adapter_available: bool = False,
        allow_composition: bool = True,
        target_language: str = "c",
        simd_benchmarked_beneficial: bool = False,
        assembly_end_to_end_proven: bool = False,
        force_forge: bool = False,
    ) -> EscalationDecision:
        """Evaluate the strict escalation ladder priority before forging a native binary."""
        trace: List[Dict[str, Any]] = []
        req_caps = [validate_safe_text(str(c), field_name="capability") for c in required_capabilities]

        # 1. Existing verified tool
        existing_match: Optional[ToolSpec] = None
        if not force_forge and registry is not None and len(req_caps) == 1:
            candidates = registry.search_capability(req_caps[0], include_unverified=False)
            for cand in candidates:
                if security_context is None or not tool_violates_security_context(cand, security_context):
                    existing_match = cand
                    break
        if existing_match is not None:
            trace.append({"tier": ForgeEscalationTier.EXISTING_TOOL.value, "status": "SELECTED", "tool_id": existing_match.tool_id})
            return EscalationDecision(
                selected_tier=ForgeEscalationTier.EXISTING_TOOL,
                ladder_trace=trace,
                existing_tool_id=existing_match.tool_id,
                reason=f"EXISTING_VERIFIED_TOOL:{existing_match.tool_id}",
            )
        trace.append({"tier": ForgeEscalationTier.EXISTING_TOOL.value, "status": "SKIPPED", "reason": "no_verified_single_tool"})

        # 2. Adapter
        if not force_forge and adapter_available:
            trace.append({"tier": ForgeEscalationTier.ADAPTER.value, "status": "SELECTED"})
            return EscalationDecision(
                selected_tier=ForgeEscalationTier.ADAPTER,
                ladder_trace=trace,
                reason="ADAPTER_BRIDGES_EXISTING_TOOL",
            )
        trace.append({"tier": ForgeEscalationTier.ADAPTER.value, "status": "SKIPPED", "reason": "no_applicable_adapter"})

        # 3. Composition
        composed_ok = False
        if not force_forge and allow_composition and registry is not None and len(req_caps) > 1:
            all_covered = True
            for cap in req_caps:
                cands = registry.search_capability(cap, include_unverified=False)
                if not any(
                    security_context is None or not tool_violates_security_context(c, security_context)
                    for c in cands
                ):
                    all_covered = False
                    break
            composed_ok = all_covered
        if composed_ok:
            trace.append({"tier": ForgeEscalationTier.COMPOSITION.value, "status": "SELECTED"})
            return EscalationDecision(
                selected_tier=ForgeEscalationTier.COMPOSITION,
                ladder_trace=trace,
                reason="COMPOSITION_COVERS_ALL_CAPABILITIES",
            )
        trace.append({"tier": ForgeEscalationTier.COMPOSITION.value, "status": "SKIPPED", "reason": "missing_capability_not_composable"})

        # 4. Python reference -> 5. Rust/C -> 6. SIMD -> 7. Assembly
        trace.append({"tier": ForgeEscalationTier.PYTHON_REFERENCE.value, "status": "ORACLE_REQUIRED"})
        if assembly_end_to_end_proven:
            trace.append({"tier": ForgeEscalationTier.RUST_OR_C.value, "status": "PASSED"})
            trace.append({"tier": ForgeEscalationTier.SIMD.value, "status": "PASSED"})
            trace.append({"tier": ForgeEscalationTier.ASSEMBLY.value, "status": "SELECTED"})
            return EscalationDecision(
                selected_tier=ForgeEscalationTier.ASSEMBLY,
                ladder_trace=trace,
                reason="ASSEMBLY_END_TO_END_PROVEN",
            )
        if simd_benchmarked_beneficial:
            trace.append({"tier": ForgeEscalationTier.RUST_OR_C.value, "status": "PASSED"})
            trace.append({"tier": ForgeEscalationTier.SIMD.value, "status": "SELECTED"})
            return EscalationDecision(
                selected_tier=ForgeEscalationTier.SIMD,
                ladder_trace=trace,
                reason="SIMD_BENCHMARKED_BENEFICIAL",
            )
        trace.append({"tier": ForgeEscalationTier.RUST_OR_C.value, "status": "SELECTED", "language": target_language})
        trace.append({"tier": ForgeEscalationTier.SIMD.value, "status": "DEFERRED", "reason": "only_if_benchmarked_beneficial"})
        trace.append({"tier": ForgeEscalationTier.ASSEMBLY.value, "status": "DEFERRED", "reason": "only_if_end_to_end_proven"})
        return EscalationDecision(
            selected_tier=ForgeEscalationTier.RUST_OR_C,
            ladder_trace=trace,
            reason=f"ESCALATED_TO_NATIVE:{target_language}",
        )

    def _reject_build(
        self,
        build: ToolBuild,
        *,
        reason: str,
        escalation: EscalationDecision,
        exec_status: ExecutionStatus = ExecutionStatus.FAIL,
        sandbox_receipt: Optional[SandboxReceipt] = None,
        benchmark_report: Optional[BenchmarkReport] = None,
    ) -> ForgeResult:
        rb_meta = dict(build.rollback_metadata)
        rb_meta["rejection_reason"] = redact_secrets_in_text(reason)
        rejected = build.transition_to(ForgeState.REJECTED, rollback_metadata=rb_meta)
        recorded = self.manifest_store.record_build(rejected, set_active=False)
        return ForgeResult(
            verified=False,
            execution_status=exec_status,
            build=recorded,
            tool_spec=None,
            escalation=escalation,
            benchmark_report=benchmark_report,
            sandbox_receipt=sandbox_receipt,
            manifest_path=self.manifest_store.storage_path,
            binary_path=None,
            reason=reason,
        )

    @staticmethod
    def _parse_sandbox_json_result(
        res: SandboxExecutionResult,
    ) -> Tuple[SandboxExecutionResult, Optional[Dict[str, Any]]]:
        if not res.passed:
            return res, None
        try:
            parsed = json.loads(res.stdout)
        except json.JSONDecodeError:
            return res, None
        if not isinstance(parsed, dict):
            return res, None
        return res, parsed

    def _run_native_json_case(
        self,
        bin_path: Path,
        payload: bytes,
        *,
        timeout_s: float = 10.0,
    ) -> Tuple[SandboxExecutionResult, Optional[Dict[str, Any]]]:
        res = self.sandbox.execute([str(bin_path)], stdin_data=payload, timeout_s=timeout_s)
        return self._parse_sandbox_json_result(res)

    def _run_native_json_file_case(
        self,
        bin_path: Path,
        input_path: Path,
        *,
        timeout_s: float = 10.0,
    ) -> Tuple[SandboxExecutionResult, Optional[Dict[str, Any]]]:
        res = self.sandbox.execute([str(bin_path), str(input_path)], timeout_s=timeout_s)
        return self._parse_sandbox_json_result(res)

    def _verify_sandbox_corpus(
        self,
        bin_path: Path,
        cases: Sequence[Tuple[str, bytes]],
        oracle_fn: Callable[[bytes], Dict[str, Any]],
        stage_label: str,
    ) -> Tuple[Optional[str], ExecutionStatus, Optional[SandboxReceipt], str]:
        """Run `cases` inside verified OS sandbox and compare each parsed output against `oracle_fn`."""
        records: List[Dict[str, Any]] = []
        last_receipt: Optional[SandboxReceipt] = None
        for case_name, payload in cases:
            res, parsed = self._run_native_json_case(bin_path, payload)
            last_receipt = res.receipt
            if res.execution_status == ExecutionStatus.SANDBOX_UNAVAILABLE:
                return (
                    None,
                    ExecutionStatus.SANDBOX_UNAVAILABLE,
                    last_receipt,
                    f"SANDBOX_UNAVAILABLE_DURING_{stage_label}:{res.receipt.reason}",
                )
            expected = oracle_fn(payload)
            if parsed is None or parsed != expected:
                return (
                    None,
                    ExecutionStatus.FAIL,
                    last_receipt,
                    f"{stage_label}_MISMATCH:{case_name}",
                )
            records.append(
                {
                    "case": case_name,
                    "in_sha256": sha256_digest(payload),
                    "out_sha256": sha256_digest(parsed),
                }
            )
        return sha256_digest(records), ExecutionStatus.PASS, last_receipt, ""

    def forge_from_gap(
        self,
        gap: CapabilityGap,
        *,
        registry: Optional[ToolRegistry] = None,
        task_spec: Optional[ForgeTaskSpec] = None,
        profile: Optional[Union[SecurityProfile, str]] = None,
        register_in_registry: bool = True,
    ) -> ForgeResult:
        """Resolve or forge a missing capability described by `CapabilityGap/1`."""
        if not isinstance(gap, CapabilityGap):
            raise ValueError("INVALID_CAPABILITY_GAP: expected CapabilityGap instance.")
        eff_spec = task_spec
        if eff_spec is None:
            targets = list(gap.missing_capabilities or gap.required_capabilities)
            merged_templates = {**FORGE_TEMPLATE_REGISTRY, **self._custom_templates}
            builder: Optional[Callable[..., ForgeTaskSpec]] = None
            for cap in targets:
                cleaned_cap = validate_safe_text(str(cap), field_name="capability")
                if cleaned_cap in merged_templates:
                    builder = merged_templates[cleaned_cap]
                    break
            if builder is None:
                raise ValueError(f"NO_SYNTHESIS_TEMPLATE_FOR_CAPABILITIES: {targets}")
            try:
                sig = inspect.signature(builder)
                accepts_gap_id = "gap_id" in sig.parameters or any(
                    p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()
                )
            except (TypeError, ValueError):
                accepts_gap_id = False
            eff_spec = builder(gap_id=gap.goal_id) if accepts_gap_id else builder()
        return self.forge_tool(
            eff_spec,
            registry=registry,
            security_context=gap.security_context,
            profile=profile or gap.security_context.profile,
            register_in_registry=register_in_registry,
        )

    def forge_tool(
        self,
        task_spec: ForgeTaskSpec,
        *,
        registry: Optional[ToolRegistry] = None,
        security_context: Optional[SecurityContext] = None,
        profile: Optional[Union[SecurityProfile, str]] = None,
        register_in_registry: bool = True,
        force_forge: bool = True,
    ) -> ForgeResult:
        """Execute the full strict monotonic forge lifecycle for `task_spec`."""
        eff_profile = (
            profile
            if isinstance(profile, SecurityProfile)
            else (SecurityProfile(str(profile).strip().upper()) if profile else self.profile)
        )
        escalation = self.evaluate_escalation_ladder(
            task_spec.capabilities,
            registry=registry,
            security_context=security_context,
            target_language=task_spec.language,
            force_forge=force_forge,
        )
        if escalation.selected_tier == ForgeEscalationTier.EXISTING_TOOL and escalation.existing_tool_id and registry:
            existing_spec = registry.get(escalation.existing_tool_id)
            if existing_spec is not None:
                existing_build = self.manifest_store.get_active_build(existing_spec.tool_id)
                if existing_build is not None:
                    return ForgeResult(
                        verified=True,
                        execution_status=ExecutionStatus.PASS,
                        build=existing_build,
                        tool_spec=existing_spec,
                        escalation=escalation,
                        manifest_path=self.manifest_store.storage_path,
                        reason=escalation.reason,
                    )

        # 1. PROPOSED
        clean_id = re.sub(r"[^A-Za-z0-9._-]+", "-", task_spec.tool_id)[:40].strip("-.") or "tool"
        build_id = f"bld-{clean_id}-{int(datetime.now(timezone.utc).timestamp())}-{secrets.token_hex(4)}"
        build = ToolBuild(
            build_id=build_id,
            tool_id=task_spec.tool_id,
            tool_version=task_spec.version,
            state=ForgeState.PROPOSED,
            gap_id=task_spec.gap_id,
            profile=eff_profile.value,
            language=task_spec.language,
        )

        # 2. SPECIFIED
        build = build.transition_to(ForgeState.SPECIFIED)

        # 3. REFERENCE_VERIFIED
        oracle_evidence: List[Dict[str, Any]] = []
        try:
            for case_name, payload in list(task_spec.unit_cases) + list(task_spec.boundary_cases):
                out = task_spec.oracle_fn(payload)
                if not isinstance(out, dict):
                    raise ValueError(f"ORACLE_RETURNED_NON_DICT:{case_name}")
                oracle_evidence.append(
                    {
                        "case": case_name,
                        "in_sha256": sha256_digest(payload),
                        "out_sha256": sha256_digest(out),
                    }
                )
        except Exception as exc:
            return self._reject_build(
                build,
                reason=f"REFERENCE_ORACLE_FAILED:{exc}",
                escalation=escalation,
            )
        oracle_hash = sha256_digest({"tool_id": task_spec.tool_id, "oracle_cases": oracle_evidence})
        build = build.transition_to(ForgeState.REFERENCE_VERIFIED, oracle_hash=oracle_hash)

        # 4. GENERATED (with static safety + secret-egress gate)
        safe_ok, safe_reasons = scan_forged_source_safety(
            task_spec.source_code,
            language=task_spec.language,
            allow_simd=task_spec.allow_simd,
            allow_assembly=task_spec.allow_assembly,
        )
        if not safe_ok:
            return self._reject_build(
                build,
                reason=f"STATIC_SAFETY_SCAN_REJECTED:{','.join(safe_reasons)}",
                escalation=escalation,
            )
        source_hash = sha256_digest(task_spec.source_code.encode("utf-8"))
        build = build.transition_to(ForgeState.GENERATED, source_hash=source_hash)

        # Confined staging directory inside `self.sandbox.workspace_root`
        stage_dir = Path(
            tempfile.mkdtemp(prefix=f"forge_{build_id}_", dir=str(self.sandbox.workspace_root))
        ).resolve()
        try:
            os.chmod(stage_dir, 0o700)
            src_ext = ".c" if task_spec.language == "c" else ".rs"
            src_path = stage_dir / f"tool{src_ext}"
            bin_path = stage_dir / "tool_bin"
            atomic_write_text(src_path, task_spec.source_code, mode=0o600)

            # 5. COMPILED inside verified OS sandbox
            if task_spec.language != "c":
                return self._reject_build(
                    build,
                    reason=f"UNSUPPORTED_NATIVE_COMPILER_FOR_STRICT_SANDBOX:{task_spec.language}",
                    escalation=escalation,
                )

            comp_res, compiler_name, compiler_ver, comp_flags = self.sandbox.compile_c(
                src_path,
                bin_path,
                flags=("-O2", "-std=c99", "-Wall", "-Wextra", "-Werror"),
            )
            if comp_res.execution_status == ExecutionStatus.SANDBOX_UNAVAILABLE:
                return self._reject_build(
                    build,
                    reason=f"SANDBOX_UNAVAILABLE:{comp_res.receipt.reason}",
                    escalation=escalation,
                    exec_status=ExecutionStatus.SANDBOX_UNAVAILABLE,
                    sandbox_receipt=comp_res.receipt,
                )
            if not comp_res.passed or not bin_path.exists():
                return self._reject_build(
                    build,
                    reason=f"COMPILATION_FAILED:rc={comp_res.exit_code}:{comp_res.stderr[:240]}",
                    escalation=escalation,
                    sandbox_receipt=comp_res.receipt,
                )

            artifact_hash = _read_binary_hash_nofollow(bin_path)
            build = build.transition_to(
                ForgeState.COMPILED,
                compiler=compiler_name,
                compiler_version=compiler_ver,
                flags=comp_flags,
                artifact_hash=artifact_hash,
            )

            # 6. SANDBOX_TESTED (unit tests executed inside OS sandbox)
            unit_test_digest, unit_status, unit_receipt, unit_err = self._verify_sandbox_corpus(
                bin_path, task_spec.unit_cases, task_spec.oracle_fn, "UNIT"
            )
            if unit_test_digest is None:
                return self._reject_build(
                    build,
                    reason=unit_err,
                    escalation=escalation,
                    exec_status=unit_status,
                    sandbox_receipt=unit_receipt,
                )
            last_sb_receipt: SandboxReceipt = unit_receipt or comp_res.receipt
            build = build.transition_to(
                ForgeState.SANDBOX_TESTED,
                unit_test_digest=unit_test_digest,
                sandbox_receipt=last_sb_receipt.to_dict(),
            )

            # 7. DIFFERENTIAL_VERIFIED (differential + boundary + 100+ seeded fuzz cases)
            if len(task_spec.fuzz_cases) < 100:
                return self._reject_build(
                    build,
                    reason=f"INSUFFICIENT_FUZZ_CASES:{len(task_spec.fuzz_cases)}<100",
                    escalation=escalation,
                )

            differential_digest, diff_status, diff_receipt, diff_err = self._verify_sandbox_corpus(
                bin_path, task_spec.differential_cases, task_spec.oracle_fn, "DIFFERENTIAL"
            )
            if differential_digest is None:
                return self._reject_build(
                    build,
                    reason=diff_err,
                    escalation=escalation,
                    exec_status=diff_status,
                    sandbox_receipt=diff_receipt,
                )

            boundary_digest, bnd_status, bnd_receipt, bnd_err = self._verify_sandbox_corpus(
                bin_path, task_spec.boundary_cases, task_spec.oracle_fn, "BOUNDARY"
            )
            if boundary_digest is None:
                return self._reject_build(
                    build,
                    reason=bnd_err,
                    escalation=escalation,
                    exec_status=bnd_status,
                    sandbox_receipt=bnd_receipt,
                )

            fuzz_named_cases = [(f"fuzz_{idx}", payload) for idx, payload in enumerate(task_spec.fuzz_cases)]
            fuzz_digest, fuzz_status, fuzz_receipt, fuzz_err = self._verify_sandbox_corpus(
                bin_path, fuzz_named_cases, task_spec.oracle_fn, "FUZZ"
            )
            if fuzz_digest is None:
                return self._reject_build(
                    build,
                    reason=fuzz_err,
                    escalation=escalation,
                    exec_status=fuzz_status,
                    sandbox_receipt=fuzz_receipt,
                )
            last_sb_receipt = fuzz_receipt or bnd_receipt or diff_receipt or last_sb_receipt

            build = build.transition_to(
                ForgeState.DIFFERENTIAL_VERIFIED,
                differential_digest=differential_digest,
                fuzz_digest=fuzz_digest,
                boundary_digest=boundary_digest,
            )

            # 8. BENCHMARKED (warmup + measured iterations inside OS sandbox vs Python baseline)
            bench_payload = task_spec.benchmark_payload or generate_kvpipe_v1_benchmark_payload(
                seed=task_spec.fuzz_seed, line_count=20000
            )
            bench_file = stage_dir / "bench_input.dat"
            fd_bench = os.open(
                str(bench_file),
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            with os.fdopen(fd_bench, "wb") as bf_handle:
                bf_handle.write(bench_payload)

            probe_file_res, probe_file_parsed = self._run_native_json_file_case(
                bin_path, bench_file, timeout_s=15.0
            )
            use_file_arg = probe_file_res.passed and probe_file_parsed == task_spec.oracle_fn(bench_payload)
            bench_runner = ToolBenchmark(warmup_iterations=2, measured_iterations=7, profile=eff_profile)

            def _cand_bench(data: bytes) -> Dict[str, Any]:
                if use_file_arg:
                    r, parsed_out = self._run_native_json_file_case(bin_path, bench_file, timeout_s=15.0)
                else:
                    r, parsed_out = self._run_native_json_case(bin_path, data, timeout_s=15.0)
                if not r.passed or parsed_out is None:
                    raise RuntimeError(f"BENCHMARK_CANDIDATE_FAILED:{r.execution_status.value}:{r.stderr[:200]}")
                return parsed_out

            try:
                bench_report = bench_runner.run(
                    candidate_fn=_cand_bench,
                    baseline_fn=task_spec.oracle_fn,
                    payload=bench_payload,
                    dataset_name=task_spec.dataset_name,
                    input_distribution=task_spec.input_distribution,
                    seed=task_spec.fuzz_seed,
                    compiler=compiler_name,
                    compiler_version=compiler_ver,
                    flags=comp_flags,
                    profile=eff_profile,
                    expected_reuses=task_spec.expected_reuses,
                    old_cost=task_spec.old_cost,
                    new_cost=task_spec.new_cost,
                    build_cost=task_spec.build_cost,
                    verify_cost=task_spec.verify_cost,
                    maintenance_reserve=task_spec.maintenance_reserve,
                    allow_exploratory_research=True,
                    verify_output_match=True,
                )
            except (AssertionError, RuntimeError, ValueError) as exc:
                return self._reject_build(
                    build,
                    reason=f"BENCHMARK_ERROR:{exc}",
                    escalation=escalation,
                    sandbox_receipt=last_sb_receipt,
                )
            if not bench_report.passed:
                return self._reject_build(
                    build,
                    reason=f"BENCHMARK_REJECTED:{bench_report.reason}",
                    escalation=escalation,
                    benchmark_report=bench_report,
                    sandbox_receipt=last_sb_receipt,
                )
            build = build.transition_to(
                ForgeState.BENCHMARKED,
                benchmark_vs_baseline=bench_report.to_dict(),
            )

            # 9. SHADOW (shadow check + rollback metadata capturing prior verified hash)
            prior_active = self.manifest_store.get_active_build(task_spec.tool_id)
            shadow_payload = task_spec.unit_cases[0][1] if task_spec.unit_cases else b"SHADOW=ok\n"
            shadow_res, shadow_parsed = self._run_native_json_case(bin_path, shadow_payload)
            if shadow_res.execution_status == ExecutionStatus.SANDBOX_UNAVAILABLE:
                return self._reject_build(
                    build,
                    reason=f"SANDBOX_UNAVAILABLE_DURING_SHADOW:{shadow_res.receipt.reason}",
                    escalation=escalation,
                    exec_status=ExecutionStatus.SANDBOX_UNAVAILABLE,
                    sandbox_receipt=shadow_res.receipt,
                    benchmark_report=bench_report,
                )
            if shadow_parsed != task_spec.oracle_fn(shadow_payload):
                return self._reject_build(
                    build,
                    reason="SHADOW_PARITY_FAILED",
                    escalation=escalation,
                    sandbox_receipt=shadow_res.receipt,
                    benchmark_report=bench_report,
                )

            rollback_meta = {
                "previous_build_id": prior_active.build_id if prior_active else "none",
                "previous_artifact_hash": prior_active.artifact_hash if prior_active else "none",
                "shadow_digest": sha256_digest(shadow_parsed),
                "sandbox_profile_hash": shadow_res.receipt.profile_hash,
            }
            build = build.transition_to(ForgeState.SHADOW, rollback_metadata=rollback_meta)

            # 10. VERIFIED -> atomic promotion into `.kintsugi/forged_tools/<tool_id>/<build_id>/`
            safe_dir_name = re.sub(r"[^A-Za-z0-9._-]+", "_", task_spec.tool_id)
            target_dir = self.forged_tools_root / safe_dir_name / build_id
            assert_not_symlink(self.forged_tools_root)
            target_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(target_dir, 0o700)

            promoted_src = target_dir / f"tool{src_ext}"
            promoted_bin = target_dir / safe_dir_name
            atomic_write_text(promoted_src, task_spec.source_code, mode=0o400)
            tmp_bin = target_dir / f".{safe_dir_name}.{secrets.token_hex(4)}.tmp"
            shutil.copy2(str(bin_path), str(tmp_bin))
            os.chmod(tmp_bin, 0o500)
            os.replace(str(tmp_bin), str(promoted_bin))

            promoted_hash = _read_binary_hash_nofollow(promoted_bin)
            if not hmac.compare_digest(promoted_hash, artifact_hash):
                raise RuntimeError("TOCTOU_PROMOTED_BINARY_HASH_MISMATCH")

            build = build.transition_to(ForgeState.VERIFIED)
            rel_entry = str(promoted_bin.relative_to(self.workspace_root))
            verification_digest = sha256_digest(
                {
                    "build_id": build.build_id,
                    "tool_id": build.tool_id,
                    "binary_hash": artifact_hash,
                    "oracle_hash": oracle_hash,
                    "differential_digest": differential_digest,
                    "fuzz_digest": fuzz_digest,
                    "boundary_digest": boundary_digest,
                    "sandbox_profile_hash": shadow_res.receipt.profile_hash,
                }
            )
            # A persisted VERIFIED tool must be signed by the registry's
            # explicitly registered authority. A standalone research forge may
            # use a per-build ephemeral signer, but cannot silently promote the
            # result to a registry which does not trust that signer.
            if (
                registry is not None and register_in_registry
                and not registry.authority.has_verifier(FORGE_VERIFIER_ID)
            ):
                if eff_profile != SecurityProfile.LOCAL_RESEARCH:
                    raise PermissionError("FORGE_VERIFIER_AUTHORITY_KEY_REQUIRED")
                # A trusted local Forge can provision an ephemeral verifier for
                # this development run only; no signing key is persisted to the
                # workspace. A later registry load without that key quarantines.
                registry.authority.register_verifier(FORGE_VERIFIER_ID, secrets.token_bytes(32))
            forge_authority = (
                registry.authority if registry is not None and registry.authority.has_verifier(FORGE_VERIFIER_ID)
                else AttestationAuthority({FORGE_VERIFIER_ID: secrets.token_bytes(32)})
            )
            placeholder_attestation = {
                "verifier_id": FORGE_VERIFIER_ID,
                "source": "native_tool_forge",
                "verification_digest": verification_digest,
                "binary_hash": artifact_hash,
                "tool_id": task_spec.tool_id,
            }
            tool_spec = ToolSpec(
                tool_id=task_spec.tool_id,
                version=task_spec.version,
                source="forge_native",
                binary_hash=artifact_hash,
                capabilities=list(task_spec.capabilities),
                input_schema=dict(task_spec.input_schema),
                output_schema=dict(task_spec.output_schema),
                semantic_contract={
                    "capability_kind": "forged_native_tool",
                    "input_port": task_spec.input_port.to_dict(),
                    "output_port": task_spec.output_port.to_dict(),
                    "effect_contract": task_spec.effect_contract.to_dict(),
                },
                preconditions=["sandbox_verified", "input_utf8_or_bytes"],
                postconditions=["deterministic_json_output", "zero_side_effects"],
                side_effects=["none"],
                required_permissions=[],
                runtime_requirements={
                    "sandbox_required": True,
                    "sandbox_backend": shadow_res.receipt.backend,
                    "language": task_spec.language,
                    "untrusted_native": False,
                    "ffi_forbidden": True,
                    "escalation_tier": escalation.selected_tier.value,
                },
                trust_status=TrustStatus.VERIFIED,
                latency_estimate_ms=round(bench_report.candidate_median_ms, 3),
                memory_estimate_mb=16.0,
                api_token_estimate=0,
                verification_attestation=placeholder_attestation,
                provenance={
                    "build_id": build.build_id,
                    "source_hash": source_hash,
                    "oracle_hash": oracle_hash,
                    "unit_test_digest": unit_test_digest,
                    "differential_digest": differential_digest,
                    "fuzz_digest": fuzz_digest,
                    "boundary_digest": boundary_digest,
                    "compiler": compiler_name,
                    "compiler_version": compiler_ver,
                    "flags": comp_flags,
                    "escalation_tier": escalation.selected_tier.value,
                },
                entrypoint=rel_entry,
                command=[rel_entry],
            )
            attestation = forge_authority.issue_attestation(
                tool_id=tool_spec.tool_id,
                binary_hash=tool_spec.binary_hash,
                verification_digest=verification_digest,
                verifier_id=FORGE_VERIFIER_ID,
                spec_digest=compute_tool_spec_security_digest(tool_spec),
            )
            attestation["source"] = "native_tool_forge"
            tool_spec.verification_attestation = attestation
            recorded_build = self.manifest_store.record_build(
                build,
                tool_spec=tool_spec,
                set_active=True,
            )

            if register_in_registry and registry is not None:
                registry.register(tool_spec, trusted_attestor=True)

            return ForgeResult(
                verified=True,
                execution_status=ExecutionStatus.PASS,
                build=recorded_build,
                tool_spec=tool_spec,
                escalation=escalation,
                benchmark_report=bench_report,
                sandbox_receipt=shadow_res.receipt,
                manifest_path=self.manifest_store.storage_path,
                binary_path=promoted_bin,
                reason="FORGE_VERIFIED",
            )
        finally:
            shutil.rmtree(stage_dir, ignore_errors=True)

    def rollback(
        self,
        tool_id: str,
        *,
        target_build_id: Optional[str] = None,
        target_artifact_hash: Optional[str] = None,
        reason: str = "manual_rollback",
        registry: Optional[ToolRegistry] = None,
    ) -> RollbackResult:
        """Atomically roll back `tool_id` to a prior verified artifact hash and sync `registry`."""
        rb = self.manifest_store.rollback(
            tool_id,
            target_build_id=target_build_id,
            target_artifact_hash=target_artifact_hash,
            reason=reason,
        )
        if registry is not None:
            if rb.restored_spec is not None:
                registry.register(rb.restored_spec, trusted_attestor=True)
            elif registry.get(rb.tool_id) is not None:
                registry.quarantine(rb.tool_id, f"ROLLED_BACK:{reason}")
        return rb


__all__ = [
    "FORGE_VERIFIER_ID",
    "DEFAULT_FORGED_TOOLS_REL_DIR",
    "FORGE_TEMPLATE_REGISTRY",
    "ForgeEscalationTier",
    "ESCALATION_LADDER_ORDER",
    "EscalationDecision",
    "ForgeTaskSpec",
    "ForgeResult",
    "NativeToolForge",
    "scan_forged_source_safety",
    "parse_kvpipe_v1_python",
    "generate_kvpipe_v1_boundary_cases",
    "generate_kvpipe_v1_fuzz_cases",
    "generate_kvpipe_v1_benchmark_payload",
    "build_kvpipe_v1_task_spec",
    "filter_jsonl_level_python",
    "generate_jsonl_level_filter_boundary_cases",
    "generate_jsonl_level_filter_fuzz_cases",
    "generate_jsonl_level_filter_benchmark_payload",
    "build_jsonl_level_filter_task_spec",
    "sum_csv_python",
    "generate_csv_sum_boundary_cases",
    "generate_csv_sum_fuzz_cases",
    "generate_csv_sum_benchmark_payload",
    "build_csv_sum_task_spec",
]
