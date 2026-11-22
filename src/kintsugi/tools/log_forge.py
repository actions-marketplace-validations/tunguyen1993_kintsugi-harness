"""LogForge (`kintsugi.tools.log_forge`): 4-Tier Tool Evolution Ladder for streaming byte scanning & event normalization.

Tiers:
  1. Python pure reference oracle (`scan_delimiters_python`, `scan_multibyte_delimiters_python`)
  2. Rust safe scalar (`kintsugi_core::kernels::scalar` / `kintsugi-rs scan-bytes --disable-simd`)
  3. Rust SIMD intrinsics (`aarch64` NEON 64B/16B & feature-gated `x86_64` AVX2) with `disable_simd` toggle
  4. Native C `<arm_neon.h>` + optional experimental AArch64 `.S` assembly probe via `ctypes`
"""

from __future__ import annotations

import ctypes
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

ByteLike = Union[bytes, bytearray, memoryview]

_EPOCH_UTC = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ISO_TS_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?(?:([Zz])|([+-])(\d{2}):?(\d{2})?)?$"
)

_LEVEL_ALIASES: Dict[str, str] = {
    "TRACE": "TRACE",
    "TRC": "TRACE",
    "DEBUG": "DEBUG",
    "DBG": "DEBUG",
    "INFO": "INFO",
    "INF": "INFO",
    "INFORMATION": "INFO",
    "WARN": "WARN",
    "WARNING": "WARN",
    "WRN": "WARN",
    "ERROR": "ERROR",
    "ERR": "ERROR",
    "FATAL": "CRITICAL",
    "CRIT": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "PANIC": "CRITICAL",
}


@dataclass(frozen=True)
class EvolutionTierSpec:
    """Metadata describing one rung of a Tool Evolution Native Kernel Ladder."""

    tier: int
    name: str
    language: str
    entrypoint: str
    production_default: bool
    notes: str = ""


@dataclass(frozen=True)
class ToolSpec:
    """Declarative specification for an evolved native-capable harness tool."""

    name: str
    version: str
    purpose: str
    tiers: Tuple[EvolutionTierSpec, ...]
    safety_policy: Tuple[str, ...]


LOGFORGE_TOOL_SPEC = ToolSpec(
    name="LogForge",
    version="1.0.0",
    purpose="Streaming delimiter/newline/JSONL/structured-log byte scanner & zero-loss event normalizer.",
    tiers=(
        EvolutionTierSpec(
            tier=1,
            name="python_oracle",
            language="python",
            entrypoint="kintsugi.tools.log_forge.scan_delimiters_python",
            production_default=False,
            notes="Pure Python semantic oracle for differential fuzzing and parity verification.",
        ),
        EvolutionTierSpec(
            tier=2,
            name="rust_scalar",
            language="rust",
            entrypoint="kintsugi_core::kernels::scalar::scan_delimiters_scalar",
            production_default=False,
            notes="Safe Rust zero-unsafe fallback (independently testable via disable_simd=True).",
        ),
        EvolutionTierSpec(
            tier=3,
            name="rust_simd",
            language="rust",
            entrypoint="kintsugi_core::kernels::byte_scanner::scan_delimiters",
            production_default=True,
            notes="Production kernel: aarch64 NEON 64B/16B intrinsics and x86_64 runtime-gated AVX2.",
        ),
        EvolutionTierSpec(
            tier=4,
            name="c_neon_and_asm_probe",
            language="c+aarch64_asm",
            entrypoint="native/c/logforge_neon_probe.c + native/asm/aarch64/delim_scan.S",
            production_default=False,
            notes="Experimental Section-J Steel/Silicon comparison probe; zero syscalls/IO.",
        ),
    ),
    safety_policy=(
        "no_syscalls_in_native_kernels",
        "no_filesystem_or_network_in_scan_kernels",
        "strict_bounds_checking",
        "shell_false_subprocess_invocation",
    ),
)


@dataclass(frozen=True)
class NormalizedLogEvent:
    """Canonical structured log event emitted without dropping raw source content."""

    record_index: int
    byte_offset: int
    byte_len: int
    format: str
    timestamp_utc: Optional[str]
    timestamp_raw: Optional[str]
    level: Optional[str]
    message: Optional[str]
    raw_preserved: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class LogScanResult:
    """Result container returned by `LogForge` delimiter & normalization calls."""

    backend: str
    disable_simd: bool
    input_bytes: int
    delim: Optional[int]
    offsets: List[int]
    events: Optional[List[NormalizedLogEvent]] = None
    elapsed_us: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize LogScanResult to JSON-ready dict."""
        return {
            "backend": self.backend,
            "disable_simd": self.disable_simd,
            "input_bytes": self.input_bytes,
            "delim": self.delim,
            "offsets": list(self.offsets),
            "events": [ev.to_dict() for ev in self.events] if self.events is not None else None,
            "elapsed_us": self.elapsed_us,
        }


def _as_byte_view(data: ByteLike) -> memoryview:
    view = memoryview(data)
    if view.format != "B":
        view = view.cast("B")
    return view


def scan_delimiters_python(data: ByteLike, delim: int = 0x0A) -> List[int]:
    """Tier 1 Python pure reference oracle returning exact 0-based byte offsets of `delim`."""
    if not isinstance(delim, int) or not (0 <= delim <= 255):
        raise ValueError(f"delim must be an int in 0..=255, got {delim!r}")
    view = _as_byte_view(data)
    return [idx for idx, byte_val in enumerate(view) if byte_val == delim]


def count_delimiters_python(data: ByteLike, delim: int = 0x0A) -> int:
    """Tier 1 Python pure reference delimiter counter."""
    if not isinstance(delim, int) or not (0 <= delim <= 255):
        raise ValueError(f"delim must be an int in 0..=255, got {delim!r}")
    view = _as_byte_view(data)
    total = 0
    for byte_val in view:
        if byte_val == delim:
            total += 1
    return total


def scan_multibyte_delimiters_python(data: ByteLike, pattern: ByteLike) -> List[int]:
    """Tier 1 Python pure reference scanner for non-overlapping left-to-right `pattern` matches."""
    raw = bytes(_as_byte_view(data))
    pat = bytes(_as_byte_view(pattern))
    m = len(pat)
    if m == 0 or len(raw) < m:
        return []
    if m == 1:
        return scan_delimiters_python(raw, pat[0])
    out: List[int] = []
    idx = 0
    limit = len(raw) - m
    first = pat[0]
    while idx <= limit:
        if raw[idx] == first and raw[idx : idx + m] == pat:
            out.append(idx)
            idx += m
        else:
            idx += 1
    return out


def _format_epoch_utc(epoch_secs: int, frac_digits: str) -> Optional[str]:
    try:
        dt = _EPOCH_UTC + timedelta(seconds=epoch_secs)
    except OverflowError:
        return None
    if not (0 <= dt.year <= 9999):
        return None
    clean_frac = frac_digits.rstrip("0")
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    if clean_frac:
        return f"{base}.{clean_frac}Z"
    return f"{base}Z"


def normalize_timestamp_utc_python(raw: str) -> Optional[str]:
    """Normalize ISO-8601/RFC-3339 or Unix epoch timestamps into canonical UTC without float rounding."""
    s = raw.strip()
    if not s:
        return None

    # 1. Numeric Unix epoch (integer s/ms/us/ns or exact decimal secs.frac)
    if all(ch.isdigit() or ch == "." for ch in s):
        if "." in s:
            parts = s.split(".")
            if len(parts) != 2 or not parts[0] or not parts[1]:
                return None
            return _format_epoch_utc(int(parts[0]), parts[1])
        val = int(s)
        digits = len(s)
        if digits >= 18:
            secs, ns = divmod(val, 1_000_000_000)
            return _format_epoch_utc(secs, f"{ns:09d}")
        if 15 <= digits <= 17:
            secs, us = divmod(val, 1_000_000)
            return _format_epoch_utc(secs, f"{us:06d}")
        if 12 <= digits <= 14:
            secs, ms = divmod(val, 1_000)
            return _format_epoch_utc(secs, f"{ms:03d}")
        return _format_epoch_utc(val, "")

    # 2. ISO-8601 / RFC-3339
    match = _ISO_TS_RE.match(s)
    if not match:
        return None
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    frac = match.group(7) or ""
    zulu = match.group(8)
    sign_str = match.group(9)
    off_h_str = match.group(10)
    off_m_str = match.group(11)

    try:
        dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None

    tz_offset_secs = 0
    if not zulu and sign_str is not None:
        oh = int(off_h_str)
        om = int(off_m_str) if off_m_str is not None else 0
        if not (0 <= oh <= 23 and 0 <= om <= 59):
            return None
        sign = 1 if sign_str == "+" else -1
        tz_offset_secs = sign * (oh * 3600 + om * 60)

    utc_dt = dt - timedelta(seconds=tz_offset_secs)
    epoch_secs = int((utc_dt - _EPOCH_UTC).total_seconds())
    return _format_epoch_utc(epoch_secs, frac)


def _canonicalize_level(raw: str) -> Optional[str]:
    return _LEVEL_ALIASES.get(raw.strip().upper())


def _parse_logfmt_pairs(trimmed: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    n = len(trimmed)
    i = 0
    while i < n:
        while i < n and trimmed[i].isspace():
            i += 1
        if i >= n:
            break
        tok_start = i
        while i < n and trimmed[i] != "=" and not trimmed[i].isspace():
            i += 1
        if i < n and trimmed[i] == "=" and i > tok_start:
            key = trimmed[tok_start:i]
            i += 1
            if i < n and trimmed[i] == '"':
                end_quote = i + 1
                buf: List[str] = []
                closed = False
                while end_quote < n:
                    ch = trimmed[end_quote]
                    if ch == "\\" and end_quote + 1 < n:
                        nxt = trimmed[end_quote + 1]
                        esc_map = {'"': '"', "\\": "\\", "n": "\n", "r": "\r", "t": "\t"}
                        buf.append(esc_map.get(nxt, nxt))
                        end_quote += 2
                        continue
                    if ch == '"':
                        closed = True
                        end_quote += 1
                        break
                    buf.append(ch)
                    end_quote += 1
                if closed:
                    out.append((key, "".join(buf)))
                    i = end_quote
                    continue
            val_start = i
            while i < n and not trimmed[i].isspace():
                i += 1
            out.append((key, trimmed[val_start:i]))
        else:
            while i < n and not trimmed[i].isspace():
                i += 1
    return out


def normalize_single_record_python(
    record_index: int,
    byte_offset: int,
    byte_len: int,
    raw_line: str,
) -> NormalizedLogEvent:
    """Normalize a single JSONL, logfmt, or timestamp-prefixed log line without losing raw content."""
    trimmed = raw_line.strip()
    if trimmed.startswith("{") and trimmed.endswith("}"):
        try:
            obj = json.loads(trimmed)
        except ValueError:
            obj = None
        if isinstance(obj, dict):
            ts_raw: Optional[str] = None
            level: Optional[str] = None
            message: Optional[str] = None
            for k, v in obj.items():
                if isinstance(v, (dict, list)) or v is None:
                    continue
                s_val = "true" if v is True else ("false" if v is False else str(v))
                kl = str(k).lower()
                if ts_raw is None and kl in ("timestamp", "ts", "time", "@timestamp", "created_at"):
                    ts_raw = s_val
                elif level is None and kl in ("level", "severity", "lvl", "log_level"):
                    level = _canonicalize_level(s_val) or s_val.upper()
                elif message is None and kl in ("message", "msg", "event", "error"):
                    message = s_val
            return NormalizedLogEvent(
                record_index=record_index,
                byte_offset=byte_offset,
                byte_len=byte_len,
                format="jsonl",
                timestamp_utc=normalize_timestamp_utc_python(ts_raw) if ts_raw is not None else None,
                timestamp_raw=ts_raw,
                level=level,
                message=message,
                raw_preserved=raw_line,
            )

    kv_pairs = _parse_logfmt_pairs(trimmed)
    if kv_pairs:
        ts_raw = None
        level = None
        message = None
        for k, v in kv_pairs:
            kl = k.lower()
            if ts_raw is None and kl in ("ts", "time", "timestamp", "@timestamp"):
                ts_raw = v
            elif level is None and kl in ("level", "lvl", "severity"):
                level = _canonicalize_level(v) or v.upper()
            elif message is None and kl in ("msg", "message", "event"):
                message = v
        if ts_raw is not None or level is not None or message is not None:
            if ts_raw is None:
                tokens = trimmed.split()
                if tokens:
                    clean_tok = tokens[0].strip("[]")
                    if normalize_timestamp_utc_python(clean_tok) is not None:
                        ts_raw = clean_tok
            return NormalizedLogEvent(
                record_index=record_index,
                byte_offset=byte_offset,
                byte_len=byte_len,
                format="structured",
                timestamp_utc=normalize_timestamp_utc_python(ts_raw) if ts_raw is not None else None,
                timestamp_raw=ts_raw,
                level=level,
                message=message,
                raw_preserved=raw_line,
            )

    tokens = trimmed.split()
    if tokens:
        first = tokens[0]
        clean_first = first.strip("[]")
        matched_ts_utc = normalize_timestamp_utc_python(clean_first)
        matched_ts_raw = clean_first
        after_idx: Optional[int] = None
        if matched_ts_utc is not None:
            pos = trimmed.find(first)
            if pos >= 0:
                after_idx = pos + len(first)
        elif (
            len(clean_first) == 10
            and clean_first[4] == "-"
            and clean_first[7] == "-"
            and len(tokens) >= 2
        ):
            second = tokens[1]
            clean_second = second.strip("[]")
            combined = f"{clean_first} {clean_second}"
            cand_utc = normalize_timestamp_utc_python(combined)
            if cand_utc is not None:
                p1 = trimmed.find(first)
                if p1 >= 0:
                    search_from = p1 + len(first)
                    rel2 = trimmed[search_from:].find(second)
                    if rel2 >= 0:
                        matched_ts_utc = cand_utc
                        matched_ts_raw = combined
                        after_idx = search_from + rel2 + len(second)

        if matched_ts_utc is not None and after_idx is not None:
            after_ts = trimmed[after_idx:].lstrip()
            rest_tokens = after_ts.split()
            lvl: Optional[str] = None
            msg_text = after_ts
            if rest_tokens:
                lvl = _canonicalize_level(rest_tokens[0])
                if lvl is not None:
                    pos_lvl = after_ts.find(rest_tokens[0])
                    msg_text = after_ts[pos_lvl + len(rest_tokens[0]) :].lstrip()
            return NormalizedLogEvent(
                record_index=record_index,
                byte_offset=byte_offset,
                byte_len=byte_len,
                format="structured",
                timestamp_utc=matched_ts_utc,
                timestamp_raw=matched_ts_raw,
                level=lvl,
                message=msg_text if msg_text else None,
                raw_preserved=raw_line,
            )

    return NormalizedLogEvent(
        record_index=record_index,
        byte_offset=byte_offset,
        byte_len=byte_len,
        format="raw",
        timestamp_utc=None,
        timestamp_raw=None,
        level=None,
        message=raw_line,
        raw_preserved=raw_line,
    )


def normalize_log_records_python(data: ByteLike, delim: int = 0x0A) -> List[NormalizedLogEvent]:
    """Tier 1 Python reference log splitter & event normalizer matching Rust `normalize_log_records`."""
    raw = bytes(_as_byte_view(data))
    offsets = scan_delimiters_python(raw, delim)
    events: List[NormalizedLogEvent] = []
    start = 0
    record_index = 0

    def _emit_slice(s: int, e: int) -> None:
        nonlocal record_index
        chunk = raw[s:e]
        if delim == 0x0A and chunk.endswith(b"\r"):
            chunk = chunk[:-1]
        if not chunk:
            return
        decoded = chunk.decode("utf-8", errors="replace")
        if not decoded.strip():
            return
        events.append(normalize_single_record_python(record_index, s, len(chunk), decoded))
        record_index += 1

    for off in offsets:
        _emit_slice(start, off)
        start = off + 1
    if start < len(raw):
        _emit_slice(start, len(raw))
    return events


class StreamingLogForgePython:
    """Streaming Python oracle scanner preserving exact global offsets across arbitrary chunk splits."""

    def __init__(self, pattern: ByteLike = b"\n") -> None:
        self.pattern = bytes(_as_byte_view(pattern))
        self.global_offset = 0
        self._tail = b""
        self._tail_start = 0

    def push_chunk(self, chunk: ByteLike) -> List[int]:
        buf = bytes(_as_byte_view(chunk))
        if not buf or not self.pattern:
            return []
        m = len(self.pattern)
        if m == 1:
            base = self.global_offset
            offs = [base + o for o in scan_delimiters_python(buf, self.pattern[0])]
            self.global_offset += len(buf)
            self._tail_start = self.global_offset
            return offs

        work = self._tail + buf
        local = scan_multibyte_delimiters_python(work, self.pattern)
        global_matches = [self._tail_start + o for o in local]
        last_consumed = (local[-1] + m) if local else 0
        keep_from = max(last_consumed, max(0, len(work) - (m - 1)))
        self._tail = work[keep_from:]
        self._tail_start += keep_from
        self.global_offset += len(buf)
        return global_matches


class LogForgeNativeBridge:
    """Subprocess bridge to the compiled `kintsugi-rs` native Rust SIMD/scalar binary."""

    def __init__(self, rust_bin: Optional[Union[str, Path]] = None) -> None:
        self.rust_bin = self._resolve_bin(rust_bin)

    @staticmethod
    def _resolve_bin(explicit: Optional[Union[str, Path]]) -> Optional[Path]:
        if explicit is not None:
            p = Path(explicit)
            return p if p.is_file() else None
        repo_root = Path(__file__).resolve().parents[3]
        for rel in ("target/release/kintsugi-rs", "target/debug/kintsugi-rs"):
            cand = repo_root / rel
            if cand.is_file():
                return cand
        return None

    def available(self) -> bool:
        return self.rust_bin is not None and self.rust_bin.is_file()

    def scan_bytes(
        self,
        data: ByteLike,
        *,
        delim: int = 0x0A,
        pattern: Optional[ByteLike] = None,
        disable_simd: bool = False,
        normalize: bool = False,
        timeout_sec: float = 15.0,
    ) -> LogScanResult:
        if self.rust_bin is None or not self.rust_bin.is_file():
            raise FileNotFoundError("Compiled kintsugi-rs binary not found")
        raw = bytes(_as_byte_view(data))
        argv = [str(self.rust_bin), "scan-bytes", "-"]
        if pattern is not None:
            pat_bytes = bytes(_as_byte_view(pattern))
            argv.extend(["--pattern-hex", pat_bytes.hex()])
        else:
            argv.extend(["--delim", f"0x{delim:02x}"])
        if disable_simd:
            argv.append("--disable-simd")
        if normalize and pattern is None:
            argv.append("--normalize")

        proc = subprocess.run(
            argv,
            input=raw,
            capture_output=True,
            shell=False,
            check=False,
            timeout=timeout_sec,
        )
        if proc.returncode != 0:
            err_msg = proc.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"kintsugi-rs scan-bytes failed (rc={proc.returncode}): {err_msg}")
        payload = json.loads(proc.stdout.decode("utf-8"))
        events: Optional[List[NormalizedLogEvent]] = None
        if "events" in payload:
            events = [
                NormalizedLogEvent(
                    record_index=int(ev["record_index"]),
                    byte_offset=int(ev["byte_offset"]),
                    byte_len=int(ev["byte_len"]),
                    format=str(ev["format"]),
                    timestamp_utc=ev["timestamp_utc"],
                    timestamp_raw=ev["timestamp_raw"],
                    level=ev["level"],
                    message=ev["message"],
                    raw_preserved=str(ev["raw_preserved"]),
                )
                for ev in payload["events"]
            ]
        return LogScanResult(
            backend=str(payload["backend"]),
            disable_simd=bool(payload["disable_simd"]),
            input_bytes=int(payload["input_bytes"]),
            delim=None if pattern is not None else int(payload["delim"]),
            offsets=[int(x) for x in payload["offsets"]],
            events=events,
            elapsed_us=float(payload["elapsed_us"]),
        )

    def benchmark(
        self,
        *,
        size_bytes: int = 1_048_576,
        warmup: int = 10,
        iters: int = 50,
        seed: int = 20261121,
        delim: int = 0x0A,
        timeout_sec: float = 60.0,
    ) -> Dict[str, Any]:
        if self.rust_bin is None or not self.rust_bin.is_file():
            raise FileNotFoundError("Compiled kintsugi-rs binary not found")
        argv = [
            str(self.rust_bin),
            "logforge-bench",
            "--size-bytes",
            str(size_bytes),
            "--warmup",
            str(warmup),
            "--iters",
            str(iters),
            "--seed",
            str(seed),
            "--delim",
            f"0x{delim:02x}",
        ]
        proc = subprocess.run(
            argv,
            capture_output=True,
            shell=False,
            check=False,
            timeout=timeout_sec,
        )
        if proc.returncode != 0:
            err_msg = proc.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"kintsugi-rs logforge-bench failed (rc={proc.returncode}): {err_msg}")
        return json.loads(proc.stdout.decode("utf-8"))


class LogForgeCtypesProbe:
    """Optional `ctypes` bridge to `native/c/logforge_neon_probe.c` (+ optional `.S` assembly) shared library."""

    def __init__(self, dylib_path: Union[str, Path]) -> None:
        self.dylib_path = Path(dylib_path)
        self._lib = ctypes.CDLL(str(self.dylib_path))
        self._configure_signatures()

    def _configure_signatures(self) -> None:
        args = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.c_uint8,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.c_size_t,
        ]
        for sym in ("logforge_c_scalar_scan_delimiters", "logforge_c_neon_scan_delimiters"):
            fn = getattr(self._lib, sym)
            fn.argtypes = args
            fn.restype = ctypes.c_size_t
        self.has_asm_symbol = hasattr(self._lib, "logforge_asm_scan_delimiters")
        if self.has_asm_symbol:
            fn_asm = getattr(self._lib, "logforge_asm_scan_delimiters")
            fn_asm.argtypes = args
            fn_asm.restype = ctypes.c_size_t

    def scan_delimiters(self, data: ByteLike, delim: int = 0x0A, *, variant: str = "c_neon") -> List[int]:
        if not (0 <= delim <= 255):
            raise ValueError(f"delim must be in 0..=255, got {delim}")
        raw = bytes(_as_byte_view(data))
        n = len(raw)
        if n == 0:
            return []
        in_buf = (ctypes.c_uint8 * n).from_buffer_copy(raw)
        out_buf = (ctypes.c_uint64 * n)()
        if variant == "c_scalar":
            fn = self._lib.logforge_c_scalar_scan_delimiters
        elif variant == "c_neon":
            fn = self._lib.logforge_c_neon_scan_delimiters
        elif variant == "asm_aarch64":
            if not self.has_asm_symbol:
                raise RuntimeError("logforge_asm_scan_delimiters symbol not present in probe library")
            fn = self._lib.logforge_asm_scan_delimiters
        else:
            raise ValueError(f"Unknown probe variant: {variant}")

        count = int(fn(in_buf, n, delim, out_buf, n))
        return [int(out_buf[i]) for i in range(min(count, n))]


class LogForge:
    """Unified high-level interface across all 4 Tool Evolution Ladder tiers."""

    spec: ToolSpec = LOGFORGE_TOOL_SPEC

    def __init__(
        self,
        *,
        rust_bin: Optional[Union[str, Path]] = None,
        probe_dylib: Optional[Union[str, Path]] = None,
    ) -> None:
        self.native = LogForgeNativeBridge(rust_bin=rust_bin)
        self.probe: Optional[LogForgeCtypesProbe] = None
        if probe_dylib is not None and Path(probe_dylib).is_file():
            self.probe = LogForgeCtypesProbe(probe_dylib)

    def scan_delimiters(
        self,
        data: ByteLike,
        delim: int = 0x0A,
        *,
        tier: str = "auto",
        disable_simd: bool = False,
        normalize: bool = False,
    ) -> LogScanResult:
        """Scan `data` for single-byte `delim` using the requested ladder tier."""
        view = _as_byte_view(data)
        if tier == "python_oracle" or (tier == "auto" and not self.native.available()):
            offsets = scan_delimiters_python(view, delim)
            events = normalize_log_records_python(view, delim) if normalize else None
            return LogScanResult(
                backend="python_oracle",
                disable_simd=True,
                input_bytes=len(view),
                delim=delim,
                offsets=offsets,
                events=events,
            )
        if tier in ("auto", "rust_simd", "rust_scalar", "rust_fallback"):
            eff_disable = disable_simd or tier in ("rust_scalar", "rust_fallback")
            return self.native.scan_bytes(
                view,
                delim=delim,
                disable_simd=eff_disable,
                normalize=normalize,
            )
        if tier in ("c_scalar", "c_neon", "asm_aarch64"):
            if self.probe is None:
                raise RuntimeError("Compiled ctypes probe library is not loaded")
            offsets = self.probe.scan_delimiters(view, delim, variant=tier)
            events = normalize_log_records_python(view, delim) if normalize else None
            return LogScanResult(
                backend=tier,
                disable_simd=(tier == "c_scalar"),
                input_bytes=len(view),
                delim=delim,
                offsets=offsets,
                events=events,
            )
        raise ValueError(f"Unsupported tier '{tier}'")
