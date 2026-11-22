"""Hardware-Accelerated ARM64/NEON Assembly & Portable C99 Native Forge (`kintsugi.forge.asm_native_forge`).

Multi-backend native kernel forge (`aarch64` NEON + inline assembly on Apple Silicon / ARM64
and portable C99 scalar fallback elsewhere) with pre-compile static safety gating, deterministic
reproducible builds, `O_NOFOLLOW` + SHA-256 pinned `ctypes.CDLL` loading, `KINTSUGI_ASM_ABI_V1`
verification, >=200-case differential fuzz parity, and `perf_counter_ns` + `Decimal` GB/s benchmarks.
"""

from __future__ import annotations

import ctypes
import dataclasses
import hmac
import json
import os
import platform
import random
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from kintsugi.capability.schemas import (
    canonical_json_dumps,
    redact_secrets_in_text,
    redact_secrets_in_value,
    sha256_digest,
    validate_safe_text,
)
from kintsugi.shield import (
    TROJAN_UNICODE_RE,
    assert_not_symlink,
    atomic_write_text,
    scan_artifact_egress,
)

KINTSUGI_ASM_ABI_VERSION = "KINTSUGI_ASM_ABI_V1"
KINTSUGI_ASM_ABI_MAGIC = 0x4B415331
SUPPORTED_ASM_ABI_VERSIONS = frozenset({KINTSUGI_ASM_ABI_VERSION})
DEFAULT_ASM_FORGE_REL_DIR = ".kintsugi/asm_forged_tools"
MAX_ASM_BUFFER_BYTES = 64 * 1024 * 1024
MAX_ASM_DYLIB_BYTES = 16 * 1024 * 1024
DEFAULT_COMPILE_TIMEOUT_S = 30.0
_QUANT_4 = Decimal("0.0001")
_BYTES_PER_MIB = Decimal("1048576")
_BYTES_PER_GIB = Decimal("1073741824")
_BYTES_PER_GB = Decimal("1000000000")
_NS_PER_SEC = Decimal("1000000000")


def _build_crc32c_python_table() -> Tuple[int, ...]:
    poly = 0x82F63B78
    table: List[int] = []
    for byte_val in range(256):
        crc = byte_val
        for _ in range(8):
            crc = (crc >> 1) ^ poly if (crc & 1) else (crc >> 1)
        table.append(crc & 0xFFFFFFFF)
    return tuple(table)


_CRC32C_PY_TABLE: Tuple[int, ...] = _build_crc32c_python_table()


def _format_crc32c_c_table() -> str:
    entries = [f"0x{val:08X}u" for val in _CRC32C_PY_TABLE]
    return ",\n".join("    " + ", ".join(entries[i : i + 8]) for i in range(0, 256, 8))


_FORBIDDEN_ASM_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    (
        "FORBIDDEN_PROCESS_EXEC_CALL",
        re.compile(
            r"\b(?:system|popen|execve|execl|execlp|execle|execv|execvp|execvpe|"
            r"fexecve|posix_spawn|posix_spawnp|fork|vfork)\s*\("
        ),
    ),
    ("FORBIDDEN_DYNAMIC_LOAD_CALL", re.compile(r"\b(?:dlopen|dlsym|dlclose|dlmopen)\s*\(")),
    (
        "FORBIDDEN_MEMORY_OR_SYSCALL_API",
        re.compile(r"\b(?:mmap|mmap64|munmap|mprotect|ptrace|syscall|__syscall)\s*\("),
    ),
    (
        "FORBIDDEN_NETWORK_CALL",
        re.compile(
            r"\b(?:socket|connect|bind|listen|accept|accept4|sendto|recvfrom|sendmsg|recvmsg|getaddrinfo)\s*\("
        ),
    ),
    (
        "FORBIDDEN_FILE_IO_CALL",
        re.compile(r"\b(?:fopen|freopen|open|openat|creat|unlink|remove|rename)\s*\("),
    ),
    (
        "FORBIDDEN_SYSTEM_HEADER",
        re.compile(
            r"#\s*include\s*<\s*(?:sys/socket\.h|netinet/|arpa/inet\.h|netdb\.h|"
            r"sys/syscall\.h|unistd\.h|dlfcn\.h|sys/mman\.h|fcntl\.h)"
        ),
    ),
    (
        "FORBIDDEN_UNSAFE_STRING_OR_FORMAT_SINK",
        re.compile(
            r"\b(?:strcpy|strcat|sprintf|vsprintf|snprintf|vsnprintf|printf|fprintf|"
            r"vprintf|vfprintf|scanf|sscanf|gets|mktemp)\s*\("
        ),
    ),
    (
        "FORBIDDEN_INLINE_ASM_SYSCALL_OR_PRIV",
        re.compile(
            r"(?:\bsvc\b|\bhvc\b|\bsmc\b|\bbrk\b|\bhlt\b|\bmrs\b|\bmsr\b|\bsysl?\b|"
            r"\bint\s+0x80\b|\bsyscall\b|\bsysenter\b|"
            r"\.(?:inst|byte|word|long|quad|ascii|asciz|incbin)\b)",
            re.IGNORECASE,
        ),
    ),
    ("FORBIDDEN_PREPROCESSOR_TOKEN_PASTE", re.compile(r"##")),
)

_DISALLOWED_NON_ASM_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("FORBIDDEN_INLINE_ASM_DISABLED", re.compile(r"\b(?:__asm__|__asm|asm)\b")),
    ("FORBIDDEN_SIMD_HEADERS_DISABLED", re.compile(r"#\s*include\s*<\s*(?:arm_neon|arm_acle)\.h\s*>")),
)


def detect_host_arch(machine: Optional[str] = None) -> str:
    """Normalize host architecture identifier (`aarch64`, `x86_64`, etc.)."""
    raw = (machine if machine is not None else platform.machine()).strip().lower()
    if raw in {"arm64", "aarch64", "arm64e"}:
        return "aarch64"
    if raw in {"x86_64", "amd64"}:
        return "x86_64"
    return raw or "unknown"


def resolve_asm_backend(
    *,
    force_scalar: bool = False,
    target_arch: Optional[str] = None,
    kernel_id: Optional[str] = None,
) -> str:
    """Resolve the active execution backend name for `target_arch` and `force_scalar`."""
    if force_scalar or detect_host_arch(target_arch) != "aarch64":
        return "portable_c99_scalar"
    return "aarch64_crc32_inline_asm" if kernel_id == "asm.crc32c_fnv64.v1" else "aarch64_neon_inline_asm"


def validate_asm_abi_version(abi_version: str) -> str:
    """Validate that `abi_version` is a known supported Kintsugi ASM ABI version."""
    cleaned = validate_safe_text(str(abi_version), field_name="abi_version")
    if cleaned not in SUPPORTED_ASM_ABI_VERSIONS:
        raise ValueError(
            f"UNSUPPORTED_ASM_ABI_VERSION: {cleaned!r}; expected one of {sorted(SUPPORTED_ASM_ABI_VERSIONS)}."
        )
    return cleaned


def scan_asm_source_safety(
    source_code: str,
    *,
    allow_asm: bool = True,
    abi_version: str = KINTSUGI_ASM_ABI_VERSION,
) -> Tuple[bool, List[str]]:
    """Run static pre-compile safety, syscall, DLP, and ABI checks on C/ASM kernel source."""
    try:
        validated_abi = validate_asm_abi_version(abi_version)
    except ValueError:
        return False, ["UNSUPPORTED_ASM_ABI_VERSION"]

    if not isinstance(source_code, str) or not source_code.strip():
        return False, ["EMPTY_SOURCE_CODE"]

    reasons: List[str] = []
    if "\x00" in source_code or TROJAN_UNICODE_RE.search(source_code):
        reasons.append("TROJAN_OR_NUL_IN_SOURCE")
    if not scan_artifact_egress(source_code, context="asm_forge_source")["ok"]:
        reasons.append("EGRESS_SECRET_OR_DLP_IN_SOURCE")

    for rule_name, pat in _FORBIDDEN_ASM_PATTERNS:
        if pat.search(source_code):
            reasons.append(rule_name)
    if not allow_asm:
        for rule_name, pat in _DISALLOWED_NON_ASM_PATTERNS:
            if pat.search(source_code):
                reasons.append(rule_name)
    if validated_abi not in source_code or "kintsugi_asm_abi_version" not in source_code:
        reasons.append("MISSING_ABI_HEADER_CONTRACT")
    return len(reasons) == 0, reasons


def _coerce_bytes(raw_input: Union[bytes, bytearray, memoryview]) -> bytes:
    if isinstance(raw_input, bytes):
        return raw_input
    if isinstance(raw_input, (bytearray, memoryview)):
        return bytes(raw_input)
    raise TypeError(f"EXPECTED_BYTES_LIKE: got {type(raw_input).__name__}")


def _validate_delim_byte(delim: int) -> int:
    if isinstance(delim, bool) or not isinstance(delim, int) or delim < 0 or delim > 255:
        raise ValueError(f"INVALID_DELIM_BYTE: expected int in 0..255, got {delim!r}")
    return delim


def delim_scan_python(raw_input: Union[bytes, bytearray, memoryview], delim: int = 10) -> List[int]:
    """Pure-Python reference oracle returning exact sorted byte offsets of `delim`."""
    delim_u8 = _validate_delim_byte(delim)
    raw = _coerce_bytes(raw_input)
    if len(raw) > MAX_ASM_BUFFER_BYTES:
        raise ValueError(f"BUFFER_TOO_LARGE: {len(raw)} > {MAX_ASM_BUFFER_BYTES}")
    offsets: List[int] = []
    append = offsets.append
    for idx, b in enumerate(raw):
        if b == delim_u8:
            append(idx)
    return offsets


def crc32c_fnv64_python(raw_input: Union[bytes, bytearray, memoryview]) -> Dict[str, int]:
    """Pure-Python reference oracle computing exact Castagnoli CRC32C and 64-bit FNV-1a."""
    raw = _coerce_bytes(raw_input)
    if len(raw) > MAX_ASM_BUFFER_BYTES:
        raise ValueError(f"BUFFER_TOO_LARGE: {len(raw)} > {MAX_ASM_BUFFER_BYTES}")
    crc = 0xFFFFFFFF
    fnv = 0xCBF29CE484222325
    fnv_prime = 0x00000100000001B3
    mask64 = 0xFFFFFFFFFFFFFFFF
    table = _CRC32C_PY_TABLE
    for b in raw:
        crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
        fnv = ((fnv ^ b) * fnv_prime) & mask64
    return {"crc32c": (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF, "fnv1a_64": fnv}


def _c_abi_preamble(kernel_id: str, backend_macro: str, hw_backend: str) -> str:
    return (
        f'#define KINTSUGI_ASM_ABI_MAGIC_VAL 0x{KINTSUGI_ASM_ABI_MAGIC:08X}u\n'
        '#define KINTSUGI_MAX_BUFFER_BYTES (64u * 1024u * 1024u)\n\n'
        'const char *kintsugi_asm_abi_version(void) {\n'
        f'    return "{KINTSUGI_ASM_ABI_VERSION}";\n'
        '}\n'
        'uint32_t kintsugi_asm_abi_magic(void) {\n'
        '    return KINTSUGI_ASM_ABI_MAGIC_VAL;\n'
        '}\n'
        'const char *kintsugi_asm_kernel_id(void) {\n'
        f'    return "{kernel_id}";\n'
        '}\n'
        'const char *kintsugi_asm_backend_name(void) {\n'
        f'#if {backend_macro}\n'
        f'    return "{hw_backend}";\n'
        '#else\n'
        '    return "portable_c99_scalar";\n'
        '#endif\n'
        '}\n'
    )


_DELIM_SCAN_ASM_C_SOURCE = (
    r"""
#include <stddef.h>
#include <stdint.h>

#if (defined(__aarch64__) || defined(__arm64__)) && defined(__ARM_NEON) && !defined(KINTSUGI_FORCE_SCALAR)
#include <arm_neon.h>
#define KINTSUGI_DELIM_USE_NEON_ASM 1
#else
#define KINTSUGI_DELIM_USE_NEON_ASM 0
#endif
"""
    + _c_abi_preamble("asm.delim_scan.v1", "KINTSUGI_DELIM_USE_NEON_ASM", "aarch64_neon_inline_asm")
    + r"""
#if KINTSUGI_DELIM_USE_NEON_ASM
static const uint8_t K_NEON_BIT_WEIGHTS[16] = {
    0x01u, 0x02u, 0x04u, 0x08u, 0x10u, 0x20u, 0x40u, 0x80u,
    0x01u, 0x02u, 0x04u, 0x08u, 0x10u, 0x20u, 0x40u, 0x80u
};

static inline uint32_t kintsugi_ctz64_asm(uint64_t mask) {
    uint64_t tz;
    __asm__(
        "rbit %0, %1\n\t"
        "clz %0, %0"
        : "=r"(tz)
        : "r"(mask)
    );
    return (uint32_t)tz;
}
#endif

int32_t kintsugi_delim_scan_v1(
    const uint8_t *data,
    size_t len,
    uint8_t delim,
    uint64_t *out_offsets,
    size_t out_cap,
    size_t *out_total_count
) {
    if (!out_total_count || len > KINTSUGI_MAX_BUFFER_BYTES) return -1;
    if ((len > 0u && !data) || (out_cap > 0u && !out_offsets)) return -1;
    if (len == 0u) {
        *out_total_count = 0u;
        return 0;
    }

    size_t total = 0u;
    size_t offset = 0u;

#if KINTSUGI_DELIM_USE_NEON_ASM
    const uint8x16_t needle = vdupq_n_u8(delim);
    const uint8x16_t weights = vld1q_u8(K_NEON_BIT_WEIGHTS);

    while (offset + 64u <= len) {
        const uint8x16_t v0 = vld1q_u8(data + offset);
        const uint8x16_t v1 = vld1q_u8(data + offset + 16u);
        const uint8x16_t v2 = vld1q_u8(data + offset + 32u);
        const uint8x16_t v3 = vld1q_u8(data + offset + 48u);

        const uint8x16_t m0 = vandq_u8(vceqq_u8(v0, needle), weights);
        const uint8x16_t m1 = vandq_u8(vceqq_u8(v1, needle), weights);
        const uint8x16_t m2 = vandq_u8(vceqq_u8(v2, needle), weights);
        const uint8x16_t m3 = vandq_u8(vceqq_u8(v3, needle), weights);

        const uint8x16_t p0 = vpaddq_u8(m0, m1);
        const uint8x16_t p1 = vpaddq_u8(m2, m3);
        const uint8x16_t p2 = vpaddq_u8(p0, p1);
        const uint8x16_t p3 = vpaddq_u8(p2, p2);

        uint64_t mask64 = vgetq_lane_u64(vreinterpretq_u64_u8(p3), 0);
#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
        mask64 = __builtin_bswap64(mask64);
#endif
        while (mask64 != 0ULL) {
            uint32_t tz = kintsugi_ctz64_asm(mask64);
            if (total < out_cap) out_offsets[total] = (uint64_t)(offset + (size_t)tz);
            total += 1u;
            mask64 &= (mask64 - 1ULL);
        }
        offset += 64u;
    }

    while (offset + 16u <= len) {
        const uint8x16_t v = vld1q_u8(data + offset);
        const uint8x16_t masked = vandq_u8(vceqq_u8(v, needle), weights);
        const uint8x16_t p0 = vpaddq_u8(masked, masked);
        const uint8x16_t p1 = vpaddq_u8(p0, p0);
        const uint8x16_t p2 = vpaddq_u8(p1, p1);
        uint16_t mask16 = vgetq_lane_u16(vreinterpretq_u16_u8(p2), 0);
#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
        mask16 = (uint16_t)((mask16 >> 8) | (mask16 << 8));
#endif
        uint64_t mask = (uint64_t)mask16;
        while (mask != 0ULL) {
            uint32_t tz = kintsugi_ctz64_asm(mask);
            if (total < out_cap) out_offsets[total] = (uint64_t)(offset + (size_t)tz);
            total += 1u;
            mask &= (mask - 1ULL);
        }
        offset += 16u;
    }
#endif

    while (offset < len) {
        if (data[offset] == delim) {
            if (total < out_cap) out_offsets[total] = (uint64_t)offset;
            total += 1u;
        }
        offset += 1u;
    }

    *out_total_count = total;
    return 0;
}
"""
)

_CRC32C_FNV64_ASM_C_SOURCE = (
    r"""
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if (defined(__aarch64__) || defined(__arm64__)) && defined(__ARM_FEATURE_CRC32) && !defined(KINTSUGI_FORCE_SCALAR)
#if defined(__ARM_ACLE)
#include <arm_acle.h>
#endif
#define KINTSUGI_CRC_USE_ARM64_ASM 1
#else
#define KINTSUGI_CRC_USE_ARM64_ASM 0
#endif

#define KINTSUGI_FNV1A_64_OFFSET 0xCBF29CE484222325ULL
#define KINTSUGI_FNV1A_64_PRIME  0x00000100000001B3ULL
"""
    + _c_abi_preamble("asm.crc32c_fnv64.v1", "KINTSUGI_CRC_USE_ARM64_ASM", "aarch64_crc32_inline_asm")
    + r"""
#if KINTSUGI_CRC_USE_ARM64_ASM
static inline uint32_t kintsugi_crc32c_impl(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    size_t i = 0u;
    while (i + 32u <= len) {
        uint64_t w0, w1, w2, w3;
        memcpy(&w0, data + i, sizeof(w0));
        memcpy(&w1, data + i + 8u, sizeof(w1));
        memcpy(&w2, data + i + 16u, sizeof(w2));
        memcpy(&w3, data + i + 24u, sizeof(w3));
        __asm__ volatile(
            "crc32cx %w0, %w0, %x1\n\t"
            "crc32cx %w0, %w0, %x2\n\t"
            "crc32cx %w0, %w0, %x3\n\t"
            "crc32cx %w0, %w0, %x4"
            : "+r"(crc)
            : "r"(w0), "r"(w1), "r"(w2), "r"(w3)
        );
        i += 32u;
    }
    while (i + 8u <= len) {
        uint64_t w;
        memcpy(&w, data + i, sizeof(w));
        __asm__ volatile("crc32cx %w0, %w0, %x1" : "+r"(crc) : "r"(w));
        i += 8u;
    }
    while (i < len) {
        uint32_t b = (uint32_t)data[i];
        __asm__ volatile("crc32cb %w0, %w0, %w1" : "+r"(crc) : "r"(b));
        i += 1u;
    }
    return ~crc;
}
#else
static const uint32_t K_CRC32C_TABLE[256] = {
"""
    + _format_crc32c_c_table()
    + r"""
};

static inline uint32_t kintsugi_crc32c_impl(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0u; i < len; i += 1u) {
        crc = K_CRC32C_TABLE[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    }
    return ~crc;
}
#endif

static inline uint64_t kintsugi_fnv1a_64_impl(const uint8_t *data, size_t len) {
    uint64_t h = KINTSUGI_FNV1A_64_OFFSET;
    size_t i = 0u;
    while (i + 4u <= len) {
        h ^= (uint64_t)data[i];
        h *= KINTSUGI_FNV1A_64_PRIME;
        h ^= (uint64_t)data[i + 1u];
        h *= KINTSUGI_FNV1A_64_PRIME;
        h ^= (uint64_t)data[i + 2u];
        h *= KINTSUGI_FNV1A_64_PRIME;
        h ^= (uint64_t)data[i + 3u];
        h *= KINTSUGI_FNV1A_64_PRIME;
        i += 4u;
    }
    while (i < len) {
        h ^= (uint64_t)data[i];
        h *= KINTSUGI_FNV1A_64_PRIME;
        i += 1u;
    }
    return h;
}

int32_t kintsugi_crc32c_fnv64_v1(
    const uint8_t *data,
    size_t len,
    uint32_t *out_crc32c,
    uint64_t *out_fnv1a_64
) {
    if (!out_crc32c || !out_fnv1a_64 || len > KINTSUGI_MAX_BUFFER_BYTES) return -1;
    if (len > 0u && !data) return -1;
    if (len == 0u) {
        *out_crc32c = 0u;
        *out_fnv1a_64 = KINTSUGI_FNV1A_64_OFFSET;
        return 0;
    }
    *out_crc32c = kintsugi_crc32c_impl(data, len);
    *out_fnv1a_64 = kintsugi_fnv1a_64_impl(data, len);
    return 0;
}
"""
)


def generate_delim_scan_cases(*, seed: int = 20261122, count: int = 200) -> List[Tuple[str, bytes, int]]:
    """Generate boundary and deterministic randomized fuzz cases for `asm.delim_scan.v1`."""
    boundary_lengths = (0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257)
    cases: List[Tuple[str, bytes, int]] = []
    for length in boundary_lengths:
        if length == 0:
            cases.extend([("boundary_empty_nl", b"", 10), ("boundary_empty_nul", b"", 0)])
            continue
        edge_buf = bytearray(b"x" * length)
        edge_buf[0] = 0x7C
        edge_buf[length - 1] = 0x7C
        for idx in (15, 16, 63, 64):
            if idx < length:
                edge_buf[idx] = 0x7C
        cases.extend(
            [
                (f"boundary_all_match_{length}", b"\n" * length, 10),
                (f"boundary_none_match_{length}", b"A" * length, 10),
                (f"boundary_embedded_nul_{length}", bytes((idx % 17) for idx in range(length)), 0),
                (f"boundary_edges_{length}", bytes(edge_buf), 0x7C),
            ]
        )

    rng = random.Random(seed)
    for idx in range(count):
        length = rng.choice([0, 1, 2, 15, 16, 17, 63, 64, 65, rng.randint(18, 2048)])
        delim = 0 if idx % 7 == 0 else (10 if idx % 3 == 0 else rng.randint(0, 255))
        buf = bytearray(rng.getrandbits(8) for _ in range(length))
        if length > 0 and idx % 5 == 0:
            step = max(1, rng.randint(1, 19))
            for pos in range(0, length, step):
                buf[pos] = delim
        cases.append((f"fuzz_delim_{idx}", bytes(buf), delim))
    return cases


def generate_crc32c_fnv64_cases(*, seed: int = 20261122, count: int = 200) -> List[Tuple[str, bytes]]:
    """Generate boundary and deterministic randomized fuzz cases for `asm.crc32c_fnv64.v1`."""
    cases: List[Tuple[str, bytes]] = [("boundary_empty", b""), ("boundary_rfc3720_123456789", b"123456789")]
    for length in (1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257):
        cases.append((f"boundary_seq_{length}", bytes((i * 29 + 7) & 0xFF for i in range(length))))
        cases.append((f"boundary_zeros_{length}", b"\x00" * length))

    rng = random.Random(seed)
    for idx in range(count):
        length = rng.choice([0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, rng.randint(66, 4096)])
        cases.append((f"fuzz_crc_{idx}", bytes(rng.getrandbits(8) for _ in range(length))))
    return cases


def generate_asm_benchmark_payload(
    *,
    size_bytes: int = 1024 * 1024,
    seed: int = 20261122,
    delim: int = 10,
) -> bytes:
    """Generate a deterministic 1 MiB benchmark buffer containing structured records and delimiters."""
    if size_bytes < 1:
        raise ValueError("INVALID_BENCHMARK_SIZE: must be >= 1.")
    rng = random.Random(seed)
    chunk_lines: List[bytes] = []
    acc = 0
    seq = 0
    delim_b = bytes([delim & 0xFF])
    while acc < size_bytes:
        val = rng.randint(1000, 99999)
        line = f"seq={seq}|svc=kintsugi|lat={val}|ok=1".encode("ascii") + delim_b
        chunk_lines.append(line)
        acc += len(line)
        seq += 1
    return b"".join(chunk_lines)[:size_bytes]


@dataclass(frozen=True)
class AsmKernelSpec:
    """Declarative specification for an audited ARM64/C99 native kernel."""

    kernel_id: str
    version: str
    abi_version: str
    description: str
    source_code: str
    oracle_fn: Callable[..., Any]
    exported_symbols: Tuple[str, ...]
    boundary_and_fuzz_cases: Sequence[Tuple[Any, ...]]
    benchmark_payload: bytes
    fuzz_seed: int = 20261122
    benchmark_delim: int = 10


def build_delim_scan_kernel_spec(
    *,
    version: str = "1.0.0",
    fuzz_seed: int = 20261122,
    fuzz_count: int = 200,
    benchmark_size_bytes: int = 1024 * 1024,
) -> AsmKernelSpec:
    """Construct the `asm.delim_scan.v1` ARM64 NEON + inline ASM `rbit`/`clz` kernel spec."""
    return AsmKernelSpec(
        kernel_id="asm.delim_scan.v1",
        version=validate_safe_text(version, field_name="version"),
        abi_version=KINTSUGI_ASM_ABI_VERSION,
        description="ARM64 NEON vceqq_u8 + inline asm rbit/clz delimiter scanner with C99 fallback.",
        source_code=_DELIM_SCAN_ASM_C_SOURCE,
        oracle_fn=delim_scan_python,
        exported_symbols=(
            "kintsugi_asm_abi_version",
            "kintsugi_asm_abi_magic",
            "kintsugi_asm_kernel_id",
            "kintsugi_asm_backend_name",
            "kintsugi_delim_scan_v1",
        ),
        boundary_and_fuzz_cases=generate_delim_scan_cases(seed=fuzz_seed, count=fuzz_count),
        benchmark_payload=generate_asm_benchmark_payload(size_bytes=benchmark_size_bytes, seed=fuzz_seed),
        fuzz_seed=fuzz_seed,
        benchmark_delim=10,
    )


def build_crc32c_fnv64_kernel_spec(
    *,
    version: str = "1.0.0",
    fuzz_seed: int = 20261122,
    fuzz_count: int = 200,
    benchmark_size_bytes: int = 1024 * 1024,
) -> AsmKernelSpec:
    """Construct the `asm.crc32c_fnv64.v1` ARM64 `crc32cx`/`crc32cb` + FNV-1a kernel spec."""
    return AsmKernelSpec(
        kernel_id="asm.crc32c_fnv64.v1",
        version=validate_safe_text(version, field_name="version"),
        abi_version=KINTSUGI_ASM_ABI_VERSION,
        description="ARM64 inline crc32cx/crc32cb + FNV-1a 64-bit checksum kernel with C99 table fallback.",
        source_code=_CRC32C_FNV64_ASM_C_SOURCE,
        oracle_fn=crc32c_fnv64_python,
        exported_symbols=(
            "kintsugi_asm_abi_version",
            "kintsugi_asm_abi_magic",
            "kintsugi_asm_kernel_id",
            "kintsugi_asm_backend_name",
            "kintsugi_crc32c_fnv64_v1",
        ),
        boundary_and_fuzz_cases=generate_crc32c_fnv64_cases(seed=fuzz_seed, count=fuzz_count),
        benchmark_payload=generate_asm_benchmark_payload(size_bytes=benchmark_size_bytes, seed=fuzz_seed),
        fuzz_seed=fuzz_seed,
    )


ASM_KERNEL_REGISTRY: Dict[str, Callable[..., AsmKernelSpec]] = {
    "asm.delim_scan.v1": build_delim_scan_kernel_spec,
    "asm.crc32c_fnv64.v1": build_crc32c_fnv64_kernel_spec,
}


@dataclass(frozen=True)
class AsmBuildManifest:
    """Deterministic content-addressed manifest for a forged native ASM/C99 kernel."""

    kernel_id: str
    version: str
    abi_version: str
    arch: str
    backend: str
    compiler: str
    compiler_version: str
    flags: Tuple[str, ...]
    source_sha256: str
    binary_sha256: str
    exported_symbols: Tuple[str, ...]
    manifest_sha256: str = ""
    schema: str = "AsmBuildManifest/1"

    def to_reproducible_dict(self) -> Dict[str, Any]:
        """Return canonical deterministic manifest payload excluding host-specific timestamps/paths."""
        return {
            "schema": self.schema,
            "kernel_id": self.kernel_id,
            "version": self.version,
            "abi_version": self.abi_version,
            "arch": self.arch,
            "backend": self.backend,
            "compiler": self.compiler,
            "compiler_version": self.compiler_version,
            "flags": list(self.flags),
            "source_sha256": self.source_sha256,
            "binary_sha256": self.binary_sha256,
            "exported_symbols": list(self.exported_symbols),
        }

    def compute_manifest_sha256(self) -> str:
        """Compute deterministic SHA-256 over the canonical manifest dictionary."""
        return sha256_digest(canonical_json_dumps(self.to_reproducible_dict()))

    def sealed(self) -> "AsmBuildManifest":
        """Return a copy with deterministic `manifest_sha256` populated."""
        return dataclasses.replace(self, manifest_sha256=self.compute_manifest_sha256())

    def to_dict(self) -> Dict[str, Any]:
        payload = self.to_reproducible_dict()
        payload["manifest_sha256"] = self.manifest_sha256 or self.compute_manifest_sha256()
        return redact_secrets_in_value(payload)

    def save_atomic(self, path: Path) -> None:
        """Persist manifest atomically without following symlinks (`0o600`)."""
        assert_not_symlink(path.parent)
        assert_not_symlink(path)
        atomic_write_text(path, canonical_json_dumps(self.to_dict()) + "\n", mode=0o600)

    @classmethod
    def load_verified(cls, path: Path) -> "AsmBuildManifest":
        """Load manifest via `O_NOFOLLOW` and verify its `manifest_sha256` integrity."""
        raw = _read_regular_bytes_nofollow(path, max_bytes=1024 * 1024)
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict) or data.get("schema") != "AsmBuildManifest/1":
            raise ValueError("INVALID_ASM_MANIFEST_SCHEMA")
        manifest = cls(
            kernel_id=str(data["kernel_id"]),
            version=str(data["version"]),
            abi_version=validate_asm_abi_version(str(data["abi_version"])),
            arch=str(data["arch"]),
            backend=str(data["backend"]),
            compiler=str(data["compiler"]),
            compiler_version=str(data["compiler_version"]),
            flags=tuple(str(f) for f in data.get("flags", [])),
            source_sha256=str(data["source_sha256"]),
            binary_sha256=str(data["binary_sha256"]),
            exported_symbols=tuple(str(s) for s in data.get("exported_symbols", [])),
            manifest_sha256=str(data.get("manifest_sha256", "")),
        )
        if not hmac.compare_digest(manifest.manifest_sha256, manifest.compute_manifest_sha256()):
            raise ValueError("TAMPERED_ASM_MANIFEST_SHA256")
        return manifest


@dataclass(frozen=True)
class AsmDifferentialReport:
    """Result of >=200-case differential & boundary parity verification."""

    kernel_id: str
    total_cases: int
    passed_cases: int
    failed_cases: int
    passed: bool
    parity_digest: str
    backend_reported: str
    abi_version_reported: str
    failures: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return redact_secrets_in_value(dataclasses.asdict(self))


@dataclass(frozen=True)
class AsmBenchmarkReport:
    """High-resolution `perf_counter_ns` & exact-Decimal GB/s throughput report."""

    kernel_id: str
    backend: str
    abi_version: str
    arch: str
    compiler: str
    compiler_version: str
    payload_bytes: int
    warmup_iterations: int
    measured_iterations: int
    native_median_ns: int
    native_p95_ns: int
    native_min_ns: int
    kernel_only_median_ns: int
    oracle_median_ns: int
    oracle_p95_ns: int
    native_throughput_mib_s: Decimal
    native_throughput_gib_s: Decimal
    native_throughput_gbps: Decimal
    kernel_only_throughput_gib_s: Decimal
    kernel_only_throughput_gbps: Decimal
    oracle_throughput_mib_s: Decimal
    speedup_decimal: Decimal
    kernel_only_speedup_decimal: Decimal
    binary_sha256: str
    manifest_sha256: str
    passed: bool

    def to_dict(self) -> Dict[str, Any]:
        raw = dataclasses.asdict(self)
        raw["schema"] = "AsmBenchmarkReport/1"
        for k, v in list(raw.items()):
            if isinstance(v, Decimal):
                raw[k] = str(v)
        return redact_secrets_in_value(raw)


@dataclass(frozen=True)
class AsmForgeResult:
    """End-to-end result emitted by `AsmNativeForge.forge_kernel`."""

    verified: bool
    kernel_id: str
    binary_path: Optional[Path]
    manifest_path: Optional[Path]
    manifest: Optional[AsmBuildManifest]
    safety_ok: bool
    safety_reasons: List[str]
    differential_report: Optional[AsmDifferentialReport] = None
    benchmark_report: Optional[AsmBenchmarkReport] = None
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return redact_secrets_in_value(
            {
                "verified": self.verified,
                "kernel_id": self.kernel_id,
                "binary_path": str(self.binary_path) if self.binary_path else None,
                "manifest_path": str(self.manifest_path) if self.manifest_path else None,
                "manifest": self.manifest.to_dict() if self.manifest else None,
                "safety_ok": self.safety_ok,
                "safety_reasons": list(self.safety_reasons),
                "differential_report": self.differential_report.to_dict() if self.differential_report else None,
                "benchmark_report": self.benchmark_report.to_dict() if self.benchmark_report else None,
                "reason": redact_secrets_in_text(self.reason),
            }
        )


def _read_regular_bytes_nofollow(file_path: Path, *, max_bytes: int = MAX_ASM_DYLIB_BYTES) -> bytes:
    """Read a regular non-symlink file safely via `O_NOFOLLOW`."""
    assert_not_symlink(file_path.parent)
    assert_not_symlink(file_path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(file_path), flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise PermissionError(f"ASM_ARTIFACT_NOT_REGULAR_FILE: {file_path}")
        if st.st_size > max_bytes:
            raise ValueError(f"ASM_ARTIFACT_TOO_LARGE: {st.st_size} > {max_bytes}")
        chunks: List[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"ASM_ARTIFACT_EXCEEDED_LIMIT: {total} > {max_bytes}")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _assert_confined_no_symlinks(path: Path, root: Path) -> None:
    try:
        rel = path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise PermissionError(f"ASM_BINARY_OUTSIDE_WORKSPACE: {path}") from exc
    cur = root
    assert_not_symlink(cur)
    for part in rel.parts:
        cur = cur / part
        assert_not_symlink(cur)


def _resolve_clang_toolchain() -> Tuple[str, str, Optional[str]]:
    """Resolve `clang` executable path, version string, and macOS SDK path with `shell=False`."""
    clang_bin: Optional[str] = None
    sdk_path: Optional[str] = None
    xcrun = shutil.which("xcrun")
    if sys.platform == "darwin" and xcrun:
        res = subprocess.run([xcrun, "--find", "clang"], shell=False, capture_output=True, text=True, timeout=5.0)
        if res.returncode == 0 and res.stdout.strip() and Path(res.stdout.strip()).exists():
            clang_bin = res.stdout.strip()
        sdk_res = subprocess.run([xcrun, "--show-sdk-path"], shell=False, capture_output=True, text=True, timeout=5.0)
        if sdk_res.returncode == 0 and sdk_res.stdout.strip() and Path(sdk_res.stdout.strip()).exists():
            sdk_path = sdk_res.stdout.strip()
    if clang_bin is None:
        clt = Path("/Library/Developer/CommandLineTools/usr/bin/clang")
        clang_bin = str(clt) if clt.exists() else shutil.which("clang")
    if not clang_bin:
        raise RuntimeError("CLANG_TOOLCHAIN_NOT_FOUND")

    ver_res = subprocess.run([clang_bin, "--version"], shell=False, capture_output=True, text=True, timeout=5.0)
    raw_ver = ver_res.stdout or ver_res.stderr or ""
    ver_line = raw_ver.splitlines()[0].strip() if raw_ver.strip() else "clang"
    return clang_bin, validate_safe_text(ver_line[:160], field_name="compiler_version"), sdk_path


def _linux_aarch64_supports_crc() -> bool:
    cpuinfo = Path("/proc/cpuinfo")
    if not cpuinfo.exists():
        return False
    try:
        return "crc32" in cpuinfo.read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return False


def _build_deterministic_clang_flags(
    *,
    arch: str,
    force_scalar: bool,
    kernel_id: str,
    dylib_name: str,
) -> List[str]:
    flags = [
        "-O3",
        "-std=c99",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-shared",
        "-fPIC",
        "-fno-ident",
        "-ffile-prefix-map=.=/kintsugi_build",
        "-fdebug-prefix-map=.=/kintsugi_build",
    ]
    if force_scalar:
        flags.append("-DKINTSUGI_FORCE_SCALAR=1")
    elif arch == "aarch64" and sys.platform != "darwin" and kernel_id == "asm.crc32c_fnv64.v1":
        if _linux_aarch64_supports_crc():
            flags.append("-march=armv8-a+crc")

    if sys.platform == "darwin":
        flags.extend([f"-Wl,-install_name,@rpath/{dylib_name}", "-Wl,-reproducible"])
    else:
        flags.extend([f"-Wl,-soname,{dylib_name}", "-Wl,--build-id=sha1"])
    return flags


def _compute_decimal_ns_stats(samples_ns: Sequence[int]) -> Tuple[int, int, int]:
    ordered = sorted(int(x) for x in samples_ns)
    n = len(ordered)
    if n == 0:
        return 0, 0, 0
    mid = n // 2
    median_ns = ordered[mid] if (n % 2 == 1) else (ordered[mid - 1] + ordered[mid]) // 2
    p95_idx = min(n - 1, max(0, ((95 * n + 99) // 100) - 1))
    return ordered[0], median_ns, ordered[p95_idx]


def _throughput_metrics_decimal(payload_bytes: int, elapsed_ns: int) -> Tuple[Decimal, Decimal, Decimal]:
    bytes_per_sec = (Decimal(int(payload_bytes)) * _NS_PER_SEC) / Decimal(max(1, int(elapsed_ns)))
    mib_s = (bytes_per_sec / _BYTES_PER_MIB).quantize(_QUANT_4, rounding=ROUND_HALF_UP)
    gib_s = (bytes_per_sec / _BYTES_PER_GIB).quantize(_QUANT_4, rounding=ROUND_HALF_UP)
    gbps = (bytes_per_sec / _BYTES_PER_GB).quantize(_QUANT_4, rounding=ROUND_HALF_UP)
    return mib_s, gib_s, gbps


class LoadedAsmKernel:
    """Verified native shared-library kernel loaded after `O_NOFOLLOW` + SHA-256 + ABI checks."""

    def __init__(
        self,
        *,
        cdll: ctypes.CDLL,
        binary_path: Path,
        binary_sha256: str,
        kernel_id: str,
        abi_version: str,
        abi_magic: int,
        backend_name: str,
    ) -> None:
        self._lib = cdll
        self.binary_path = binary_path
        self.binary_sha256 = binary_sha256
        self.kernel_id = kernel_id
        self.abi_version = abi_version
        self.abi_magic = abi_magic
        self.backend_name = backend_name
        self._lock = threading.Lock()
        self._scratch_cap = 0
        self._scratch_buf: Any = None
        if hasattr(self._lib, "kintsugi_delim_scan_v1"):
            fn = self._lib.kintsugi_delim_scan_v1
            fn.argtypes = [
                ctypes.c_char_p,
                ctypes.c_size_t,
                ctypes.c_uint8,
                ctypes.POINTER(ctypes.c_uint64),
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_size_t),
            ]
            fn.restype = ctypes.c_int32
        if hasattr(self._lib, "kintsugi_crc32c_fnv64_v1"):
            fn_crc = self._lib.kintsugi_crc32c_fnv64_v1
            fn_crc.argtypes = [
                ctypes.c_char_p,
                ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_uint32),
                ctypes.POINTER(ctypes.c_uint64),
            ]
            fn_crc.restype = ctypes.c_int32

    def _ensure_scratch(self, min_cap: int) -> Any:
        req = max(256, int(min_cap))
        if self._scratch_buf is None or self._scratch_cap < req:
            self._scratch_buf = (ctypes.c_uint64 * req)()
            self._scratch_cap = req
        return self._scratch_buf

    def _invoke_delim_scan(
        self,
        raw_input: Union[bytes, bytearray, memoryview],
        delim: int,
        *,
        copy_offsets: bool,
    ) -> Union[List[int], int]:
        if self.kernel_id != "asm.delim_scan.v1":
            raise ValueError(f"KERNEL_MISMATCH: loaded {self.kernel_id!r}, expected 'asm.delim_scan.v1'")
        delim_u8 = _validate_delim_byte(delim)
        raw = _coerce_bytes(raw_input)
        n = len(raw)
        if n > MAX_ASM_BUFFER_BYTES:
            raise ValueError(f"BUFFER_TOO_LARGE: {n} > {MAX_ASM_BUFFER_BYTES}")
        if n == 0:
            return [] if copy_offsets else 0
        total = ctypes.c_size_t(0)
        with self._lock:
            buf = self._ensure_scratch(max(256, min(n, 65536)))
            rc = self._lib.kintsugi_delim_scan_v1(raw, n, delim_u8, buf, self._scratch_cap, ctypes.byref(total))
            if rc != 0:
                raise RuntimeError(f"NATIVE_DELIM_SCAN_FAILED:rc={rc}")
            count = int(total.value)
            if not copy_offsets:
                return count
            if count > self._scratch_cap:
                buf = self._ensure_scratch(count)
                rc = self._lib.kintsugi_delim_scan_v1(raw, n, delim_u8, buf, self._scratch_cap, ctypes.byref(total))
                if rc != 0:
                    raise RuntimeError(f"NATIVE_DELIM_SCAN_RETRY_FAILED:rc={rc}")
            return list(buf[:count])

    def delim_scan_raw_count(self, raw_input: Union[bytes, bytearray, memoryview], delim: int = 10) -> int:
        """Invoke compiled `kintsugi_delim_scan_v1` and return exact match count without list copy."""
        return int(self._invoke_delim_scan(raw_input, delim, copy_offsets=False))  # type: ignore[arg-type]

    def delim_scan(self, raw_input: Union[bytes, bytearray, memoryview], delim: int = 10) -> List[int]:
        """Invoke compiled `kintsugi_delim_scan_v1` and return exact sorted offset list."""
        return list(self._invoke_delim_scan(raw_input, delim, copy_offsets=True))  # type: ignore[arg-type]

    def crc32c_fnv64(self, raw_input: Union[bytes, bytearray, memoryview]) -> Dict[str, int]:
        """Invoke compiled `kintsugi_crc32c_fnv64_v1` returning `{crc32c, fnv1a_64}`."""
        if self.kernel_id != "asm.crc32c_fnv64.v1":
            raise ValueError(f"KERNEL_MISMATCH: loaded {self.kernel_id!r}, expected 'asm.crc32c_fnv64.v1'")
        raw = _coerce_bytes(raw_input)
        n = len(raw)
        if n > MAX_ASM_BUFFER_BYTES:
            raise ValueError(f"BUFFER_TOO_LARGE: {n} > {MAX_ASM_BUFFER_BYTES}")
        out_crc = ctypes.c_uint32(0)
        out_fnv = ctypes.c_uint64(0)
        rc = self._lib.kintsugi_crc32c_fnv64_v1(
            raw if n > 0 else b"", n, ctypes.byref(out_crc), ctypes.byref(out_fnv)
        )
        if rc != 0:
            raise RuntimeError(f"NATIVE_CRC32C_FNV64_FAILED:rc={rc}")
        return {"crc32c": int(out_crc.value), "fnv1a_64": int(out_fnv.value)}


@dataclass(frozen=True)
class _KernelDispatchEntry:
    run_case: Callable[[LoadedAsmKernel, AsmKernelSpec, Tuple[Any, ...]], Tuple[str, Any, Any, Dict[str, Any]]]
    make_bench_fns: Callable[[LoadedAsmKernel, AsmKernelSpec], Tuple[Callable[[bytes], Any], Callable[[bytes], Any], Callable[[bytes], Any]]]


def _dispatch_delim_case(
    loaded: LoadedAsmKernel, spec: AsmKernelSpec, case: Tuple[Any, ...]
) -> Tuple[str, Any, Any, Dict[str, Any]]:
    case_name, payload, delim = case
    return str(case_name), spec.oracle_fn(payload, delim), loaded.delim_scan(payload, delim), {
        "case": case_name,
        "len": len(payload),
        "delim": delim,
    }


def _dispatch_delim_bench(
    loaded: LoadedAsmKernel, spec: AsmKernelSpec
) -> Tuple[Callable[[bytes], Any], Callable[[bytes], Any], Callable[[bytes], Any]]:
    delim = spec.benchmark_delim
    return (
        lambda data: spec.oracle_fn(data, delim),
        lambda data: loaded.delim_scan(data, delim),
        lambda data: loaded.delim_scan_raw_count(data, delim),
    )


def _dispatch_crc_case(
    loaded: LoadedAsmKernel, spec: AsmKernelSpec, case: Tuple[Any, ...]
) -> Tuple[str, Any, Any, Dict[str, Any]]:
    case_name, payload = case
    return str(case_name), spec.oracle_fn(payload), loaded.crc32c_fnv64(payload), {
        "case": case_name,
        "len": len(payload),
    }


def _dispatch_crc_bench(
    loaded: LoadedAsmKernel, spec: AsmKernelSpec
) -> Tuple[Callable[[bytes], Any], Callable[[bytes], Any], Callable[[bytes], Any]]:
    return spec.oracle_fn, loaded.crc32c_fnv64, loaded.crc32c_fnv64


_KERNEL_DISPATCH: Dict[str, _KernelDispatchEntry] = {
    "asm.delim_scan.v1": _KernelDispatchEntry(_dispatch_delim_case, _dispatch_delim_bench),
    "asm.crc32c_fnv64.v1": _KernelDispatchEntry(_dispatch_crc_case, _dispatch_crc_bench),
}


class AsmNativeForge:
    """Multi-backend ARM64 NEON/Inline-ASM + Portable C99 Native Tool Forge."""

    def __init__(self, workspace_root: Union[str, Path], *, force_scalar: bool = False) -> None:
        raw_ws = Path(str(workspace_root))
        assert_not_symlink(raw_ws)
        raw_ws.mkdir(parents=True, exist_ok=True)
        self.workspace_root: Path = raw_ws.resolve()
        self.force_scalar: bool = bool(force_scalar)
        self.forged_root: Path = self.workspace_root / DEFAULT_ASM_FORGE_REL_DIR
        self.staging_root: Path = self.workspace_root / ".kintsugi" / "asm_staging"
        for d in (self.workspace_root / ".kintsugi", self.forged_root, self.staging_root):
            assert_not_symlink(d)
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)

    def _safe_kernel_slug(self, kernel_id: str) -> str:
        cleaned = validate_safe_text(kernel_id, field_name="kernel_id")
        slug = re.sub(r"[^A-Za-z0-9._-]+", "_", cleaned).strip("._-")
        if not slug:
            raise ValueError(f"INVALID_KERNEL_ID: {kernel_id!r}")
        return slug

    def compile_kernel(
        self,
        spec: AsmKernelSpec,
        *,
        force_scalar: Optional[bool] = None,
    ) -> Tuple[Path, AsmBuildManifest, Path]:
        """Validate safety + ABI, compile deterministically via `clang -O3`, and emit manifest."""
        abi_ver = validate_asm_abi_version(spec.abi_version)
        safe_ok, safe_reasons = scan_asm_source_safety(spec.source_code, allow_asm=True, abi_version=abi_ver)
        if not safe_ok:
            raise ValueError(f"STATIC_SAFETY_REJECTED:{','.join(safe_reasons)}")

        eff_scalar = self.force_scalar if force_scalar is None else bool(force_scalar)
        arch = detect_host_arch()
        backend = resolve_asm_backend(force_scalar=eff_scalar, target_arch=arch, kernel_id=spec.kernel_id)
        clang_bin, clang_ver, sdk_path = _resolve_clang_toolchain()
        slug = self._safe_kernel_slug(spec.kernel_id)
        dylib_name = f"{slug}{'.dylib' if sys.platform == 'darwin' else '.so'}"
        flags = _build_deterministic_clang_flags(
            arch=arch, force_scalar=eff_scalar, kernel_id=spec.kernel_id, dylib_name=dylib_name
        )
        source_sha256 = sha256_digest(spec.source_code.encode("utf-8"))

        stage_dir = Path(tempfile.mkdtemp(prefix=f"asm_stage_{slug}_", dir=str(self.staging_root))).resolve()
        try:
            os.chmod(stage_dir, 0o700)
            atomic_write_text(stage_dir / "kernel.c", spec.source_code, mode=0o600)
            clean_env: Dict[str, str] = {
                "PATH": "/usr/bin:/bin:/opt/homebrew/bin:/Library/Developer/CommandLineTools/usr/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "TMPDIR": str(stage_dir),
                "HOME": str(stage_dir),
                "ZERO_AR_DATE": "1",
                "SOURCE_DATE_EPOCH": "0",
            }
            if sdk_path:
                clean_env["SDKROOT"] = sdk_path
            comp = subprocess.run(
                [clang_bin, *flags, "kernel.c", "-o", dylib_name],
                shell=False,
                cwd=str(stage_dir),
                env=clean_env,
                capture_output=True,
                text=True,
                timeout=DEFAULT_COMPILE_TIMEOUT_S,
            )
            stage_bin = stage_dir / dylib_name
            if comp.returncode != 0 or not stage_bin.exists():
                raise RuntimeError(f"ASM_COMPILATION_FAILED:rc={comp.returncode}:{(comp.stderr or comp.stdout or '').strip()[:300]}")

            staged_bytes = _read_regular_bytes_nofollow(stage_bin)
            staged_sha256 = sha256_digest(staged_bytes)

            target_dir = self.forged_root / slug / backend / source_sha256[7:23]
            assert_not_symlink(self.forged_root)
            target_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(target_dir, 0o700)

            promoted_bin = target_dir / dylib_name
            manifest_path = target_dir / "build_manifest.json"
            atomic_write_text(target_dir / "kernel.c", spec.source_code, mode=0o400)
            tmp_bin = target_dir / f".{dylib_name}.{os.getpid()}.tmp"
            assert_not_symlink(tmp_bin)
            fd = os.open(str(tmp_bin), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o500)
            try:
                os.write(fd, staged_bytes)
            finally:
                os.close(fd)
            os.chmod(tmp_bin, 0o500)
            os.replace(str(tmp_bin), str(promoted_bin))

            promoted_sha256 = sha256_digest(_read_regular_bytes_nofollow(promoted_bin))
            if not hmac.compare_digest(promoted_sha256, staged_sha256):
                raise RuntimeError("TOCTOU_PROMOTED_DYLIB_SHA256_MISMATCH")

            manifest = AsmBuildManifest(
                kernel_id=spec.kernel_id,
                version=spec.version,
                abi_version=abi_ver,
                arch=arch,
                backend=backend,
                compiler=Path(clang_bin).name,
                compiler_version=clang_ver,
                flags=tuple(flags),
                source_sha256=source_sha256,
                binary_sha256=promoted_sha256,
                exported_symbols=tuple(spec.exported_symbols),
            ).sealed()
            manifest.save_atomic(manifest_path)
            return promoted_bin, manifest, manifest_path
        finally:
            shutil.rmtree(stage_dir, ignore_errors=True)

    def load_verified_kernel(
        self,
        binary_path: Union[str, Path],
        *,
        expected_sha256: str,
        expected_kernel_id: str,
        expected_abi_version: str = KINTSUGI_ASM_ABI_VERSION,
    ) -> LoadedAsmKernel:
        """Verify `O_NOFOLLOW` + SHA-256 + workspace confinement before `ctypes.CDLL` load and ABI check."""
        validate_asm_abi_version(expected_abi_version)
        bin_p = Path(binary_path)
        _assert_confined_no_symlinks(bin_p, self.workspace_root)
        actual_sha256 = sha256_digest(_read_regular_bytes_nofollow(bin_p))
        if not hmac.compare_digest(actual_sha256, expected_sha256):
            raise PermissionError(f"ASM_BINARY_SHA256_MISMATCH: expected={expected_sha256}, actual={actual_sha256}")

        lib = ctypes.CDLL(str(bin_p), mode=getattr(ctypes, "RTLD_LOCAL", ctypes.DEFAULT_MODE))
        abi_syms = (
            ("kintsugi_asm_abi_version", ctypes.c_char_p),
            ("kintsugi_asm_abi_magic", ctypes.c_uint32),
            ("kintsugi_asm_kernel_id", ctypes.c_char_p),
            ("kintsugi_asm_backend_name", ctypes.c_char_p),
        )
        for sym, restype in abi_syms:
            if not hasattr(lib, sym):
                raise RuntimeError(f"MISSING_ABI_SYMBOL: {sym}")
            fn = getattr(lib, sym)
            fn.argtypes = []
            fn.restype = restype

        reported_abi = (lib.kintsugi_asm_abi_version() or b"").decode("ascii", errors="replace")
        reported_magic = int(lib.kintsugi_asm_abi_magic())
        reported_kid = (lib.kintsugi_asm_kernel_id() or b"").decode("ascii", errors="replace")
        reported_backend = (lib.kintsugi_asm_backend_name() or b"").decode("ascii", errors="replace")

        if not hmac.compare_digest(reported_abi, expected_abi_version):
            raise ValueError(f"ABI_VERSION_MISMATCH: expected={expected_abi_version!r}, got={reported_abi!r}")
        if reported_magic != KINTSUGI_ASM_ABI_MAGIC:
            raise ValueError(f"ABI_MAGIC_MISMATCH: got=0x{reported_magic:08x}")
        if not hmac.compare_digest(reported_kid, expected_kernel_id):
            raise ValueError(f"KERNEL_ID_MISMATCH: expected={expected_kernel_id!r}, got={reported_kid!r}")

        return LoadedAsmKernel(
            cdll=lib,
            binary_path=bin_p,
            binary_sha256=actual_sha256,
            kernel_id=reported_kid,
            abi_version=reported_abi,
            abi_magic=reported_magic,
            backend_name=reported_backend,
        )

    def run_differential_fuzz(self, loaded: LoadedAsmKernel, spec: AsmKernelSpec) -> AsmDifferentialReport:
        """Verify >=200 boundary + randomized cases against `spec.oracle_fn`."""
        entry = _KERNEL_DISPATCH.get(spec.kernel_id)
        if entry is None:
            raise ValueError(f"UNSUPPORTED_KERNEL_ID: {spec.kernel_id}")
        passed = 0
        failures: List[Dict[str, str]] = []
        transcript_hashes: List[str] = []

        for case in spec.boundary_and_fuzz_cases:
            case_name, expected, actual, meta = entry.run_case(loaded, spec, case)
            if actual == expected:
                passed += 1
                transcript_hashes.append(sha256_digest({"in": sha256_digest(meta), "out": actual}))
            else:
                failures.append({"case": case_name, "reason": "ORACLE_PARITY_MISMATCH"})

        total = len(spec.boundary_and_fuzz_cases)
        return AsmDifferentialReport(
            kernel_id=spec.kernel_id,
            total_cases=total,
            passed_cases=passed,
            failed_cases=len(failures),
            passed=(len(failures) == 0 and total >= 200),
            parity_digest=sha256_digest(transcript_hashes),
            backend_reported=loaded.backend_name,
            abi_version_reported=loaded.abi_version,
            failures=failures[:10],
        )

    def run_benchmark(
        self,
        loaded: LoadedAsmKernel,
        spec: AsmKernelSpec,
        manifest: AsmBuildManifest,
        *,
        warmup_iterations: int = 3,
        measured_iterations: int = 9,
    ) -> AsmBenchmarkReport:
        """Benchmark native kernel vs Python oracle on 1 MiB payload using `perf_counter_ns` and `Decimal`."""
        entry = _KERNEL_DISPATCH.get(spec.kernel_id)
        if entry is None:
            raise ValueError(f"UNSUPPORTED_KERNEL_ID: {spec.kernel_id}")
        oracle_fn, native_fn, kernel_only_fn = entry.make_bench_fns(loaded, spec)
        payload = spec.benchmark_payload

        for _ in range(warmup_iterations):
            if native_fn(payload) != oracle_fn(payload):
                raise AssertionError("ASM_BENCHMARK_WARMUP_MISMATCH")
            _ = kernel_only_fn(payload)

        oracle_ns_samples: List[int] = []
        native_ns_samples: List[int] = []
        kernel_only_ns_samples: List[int] = []

        for _ in range(measured_iterations):
            t0 = time.perf_counter_ns()
            expected = oracle_fn(payload)
            t1 = time.perf_counter_ns()
            oracle_ns_samples.append(max(1, t1 - t0))

            t2 = time.perf_counter_ns()
            actual = native_fn(payload)
            t3 = time.perf_counter_ns()
            native_ns_samples.append(max(1, t3 - t2))
            if actual != expected:
                raise AssertionError("ASM_BENCHMARK_MEASUREMENT_MISMATCH")

            t4 = time.perf_counter_ns()
            _ = kernel_only_fn(payload)
            t5 = time.perf_counter_ns()
            kernel_only_ns_samples.append(max(1, t5 - t4))

        native_min_ns, native_med_ns, native_p95_ns = _compute_decimal_ns_stats(native_ns_samples)
        _, kernel_only_med_ns, _ = _compute_decimal_ns_stats(kernel_only_ns_samples)
        _, oracle_med_ns, oracle_p95_ns = _compute_decimal_ns_stats(oracle_ns_samples)

        n_bytes = len(payload)
        nat_mib_s, nat_gib_s, nat_gbps = _throughput_metrics_decimal(n_bytes, native_med_ns)
        _, kern_gib_s, kern_gbps = _throughput_metrics_decimal(n_bytes, kernel_only_med_ns)
        orc_mib_s, _, _ = _throughput_metrics_decimal(n_bytes, oracle_med_ns)
        speedup_dec = (Decimal(oracle_med_ns) / Decimal(max(1, native_med_ns))).quantize(
            _QUANT_4, rounding=ROUND_HALF_UP
        )
        kern_speedup_dec = (Decimal(oracle_med_ns) / Decimal(max(1, kernel_only_med_ns))).quantize(
            _QUANT_4, rounding=ROUND_HALF_UP
        )

        return AsmBenchmarkReport(
            kernel_id=spec.kernel_id,
            backend=loaded.backend_name,
            abi_version=loaded.abi_version,
            arch=manifest.arch,
            compiler=manifest.compiler,
            compiler_version=manifest.compiler_version,
            payload_bytes=n_bytes,
            warmup_iterations=warmup_iterations,
            measured_iterations=measured_iterations,
            native_median_ns=native_med_ns,
            native_p95_ns=native_p95_ns,
            native_min_ns=native_min_ns,
            kernel_only_median_ns=kernel_only_med_ns,
            oracle_median_ns=oracle_med_ns,
            oracle_p95_ns=oracle_p95_ns,
            native_throughput_mib_s=nat_mib_s,
            native_throughput_gib_s=nat_gib_s,
            native_throughput_gbps=nat_gbps,
            kernel_only_throughput_gib_s=kern_gib_s,
            kernel_only_throughput_gbps=kern_gbps,
            oracle_throughput_mib_s=orc_mib_s,
            speedup_decimal=speedup_dec,
            kernel_only_speedup_decimal=kern_speedup_dec,
            binary_sha256=manifest.binary_sha256,
            manifest_sha256=manifest.manifest_sha256,
            passed=(speedup_dec > Decimal("1.0000")),
        )

    def forge_kernel(
        self,
        spec: AsmKernelSpec,
        *,
        force_scalar: Optional[bool] = None,
        warmup_iterations: int = 3,
        measured_iterations: int = 9,
    ) -> AsmForgeResult:
        """Execute full static safety, deterministic build, SHA-256 load, 200+ fuzz, and benchmark."""
        try:
            bin_path, _, manifest_path = self.compile_kernel(spec, force_scalar=force_scalar)
        except ValueError as exc:
            err = str(exc)
            reasons = err.split(":", 1)[1].split(",") if err.startswith("STATIC_SAFETY_REJECTED:") else [err]
            return AsmForgeResult(
                verified=False,
                kernel_id=spec.kernel_id,
                binary_path=None,
                manifest_path=None,
                manifest=None,
                safety_ok=False,
                safety_reasons=reasons,
                reason=err,
            )

        loaded_manifest = AsmBuildManifest.load_verified(manifest_path)
        loaded = self.load_verified_kernel(
            bin_path,
            expected_sha256=loaded_manifest.binary_sha256,
            expected_kernel_id=spec.kernel_id,
            expected_abi_version=spec.abi_version,
        )
        diff_report = self.run_differential_fuzz(loaded, spec)
        if not diff_report.passed:
            return AsmForgeResult(
                verified=False,
                kernel_id=spec.kernel_id,
                binary_path=bin_path,
                manifest_path=manifest_path,
                manifest=loaded_manifest,
                safety_ok=True,
                safety_reasons=[],
                differential_report=diff_report,
                reason=f"DIFFERENTIAL_FUZZ_FAILED:failed={diff_report.failed_cases}",
            )

        bench_report = self.run_benchmark(
            loaded,
            spec,
            loaded_manifest,
            warmup_iterations=warmup_iterations,
            measured_iterations=measured_iterations,
        )
        return AsmForgeResult(
            verified=bool(diff_report.passed and bench_report.passed),
            kernel_id=spec.kernel_id,
            binary_path=bin_path,
            manifest_path=manifest_path,
            manifest=loaded_manifest,
            safety_ok=True,
            safety_reasons=[],
            differential_report=diff_report,
            benchmark_report=bench_report,
            reason="ASM_FORGE_VERIFIED" if bench_report.passed else "BENCHMARK_NO_SPEEDUP",
        )


__all__ = [
    "ASM_KERNEL_REGISTRY",
    "DEFAULT_ASM_FORGE_REL_DIR",
    "KINTSUGI_ASM_ABI_MAGIC",
    "KINTSUGI_ASM_ABI_VERSION",
    "MAX_ASM_BUFFER_BYTES",
    "MAX_ASM_DYLIB_BYTES",
    "SUPPORTED_ASM_ABI_VERSIONS",
    "AsmBenchmarkReport",
    "AsmBuildManifest",
    "AsmDifferentialReport",
    "AsmForgeResult",
    "AsmKernelSpec",
    "AsmNativeForge",
    "LoadedAsmKernel",
    "build_crc32c_fnv64_kernel_spec",
    "build_delim_scan_kernel_spec",
    "crc32c_fnv64_python",
    "delim_scan_python",
    "detect_host_arch",
    "generate_asm_benchmark_payload",
    "generate_crc32c_fnv64_cases",
    "generate_delim_scan_cases",
    "resolve_asm_backend",
    "scan_asm_source_safety",
    "validate_asm_abi_version",
]
