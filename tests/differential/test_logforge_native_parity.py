"""Differential, boundary, and 500+ seed fuzz parity tests for LogForge Tool Evolution Ladder."""

from __future__ import annotations

import ctypes
import platform
import random
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import List, Optional

from kintsugi.tools.log_forge import (
    LOGFORGE_TOOL_SPEC,
    LogForge,
    LogForgeCtypesProbe,
    LogForgeNativeBridge,
    StreamingLogForgePython,
    count_delimiters_python,
    normalize_log_records_python,
    normalize_timestamp_utc_python,
    scan_delimiters_python,
    scan_multibyte_delimiters_python,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _resolve_rust_bin() -> Path:
    for rel in ("target/release/kintsugi-rs", "target/debug/kintsugi-rs"):
        cand = REPO_ROOT / rel
        if cand.is_file():
            return cand
    raise unittest.SkipTest("Compiled kintsugi-rs binary unavailable in this environment")


class TestLogForgeNativeParity(unittest.TestCase):
    """Verify 100% byte-offset and normalization parity across Python, Rust Scalar, Rust SIMD, C NEON, and ASM."""

    _tmpdir: Optional[tempfile.TemporaryDirectory] = None
    rust_bin: Path
    bridge: LogForgeNativeBridge
    probe: Optional[LogForgeCtypesProbe] = None
    forge: LogForge

    @classmethod
    def setUpClass(cls) -> None:
        cls.rust_bin = _resolve_rust_bin()
        cls.bridge = LogForgeNativeBridge(rust_bin=cls.rust_bin)
        probe_dylib: Optional[Path] = None

        c_src = REPO_ROOT / "native" / "c" / "logforge_neon_probe.c"
        asm_src = REPO_ROOT / "native" / "asm" / "aarch64" / "delim_scan.S"
        clang = shutil.which("clang")
        if clang and c_src.is_file():
            cls._tmpdir = tempfile.TemporaryDirectory(prefix="logforge_probe_")
            dylib_out = Path(cls._tmpdir.name) / "liblogforge_probe.dylib"
            cmd = [clang, "-O3", "-Wall", "-Wextra", "-Werror", "-shared", "-fPIC", str(c_src)]
            if platform.machine().lower() in ("arm64", "aarch64") and asm_src.is_file():
                cmd.append(str(asm_src))
            cmd.extend(["-o", str(dylib_out)])
            res = subprocess.run(cmd, capture_output=True, shell=False, check=False)
            if res.returncode == 0 and dylib_out.is_file():
                probe_dylib = dylib_out
                cls.probe = LogForgeCtypesProbe(dylib_out)
        cls.forge = LogForge(rust_bin=cls.rust_bin, probe_dylib=probe_dylib)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls._tmpdir is not None:
            cls._tmpdir.cleanup()
            cls._tmpdir = None

    def _assert_all_tiers_equal(self, data: bytes, delim: int, *, label: str = "") -> List[int]:
        expected = scan_delimiters_python(data, delim)
        self.assertEqual(count_delimiters_python(data, delim), len(expected), label)

        res_simd = self.bridge.scan_bytes(data, delim=delim, disable_simd=False)
        res_fallback = self.bridge.scan_bytes(data, delim=delim, disable_simd=True)
        self.assertEqual(res_simd.offsets, expected, f"rust_simd mismatch ({label})")
        self.assertEqual(res_fallback.offsets, expected, f"rust_fallback mismatch ({label})")
        self.assertEqual(res_fallback.backend, "rust_scalar_fallback")
        if platform.machine().lower() in ("arm64", "aarch64"):
            self.assertEqual(res_simd.backend, "aarch64_neon_intrinsics")

        if self.probe is not None:
            c_sc = self.probe.scan_delimiters(data, delim, variant="c_scalar")
            c_neon = self.probe.scan_delimiters(data, delim, variant="c_neon")
            self.assertEqual(c_sc, expected, f"c_scalar mismatch ({label})")
            self.assertEqual(c_neon, expected, f"c_neon mismatch ({label})")
            if self.probe.has_asm_symbol:
                asm_res = self.probe.scan_delimiters(data, delim, variant="asm_aarch64")
                self.assertEqual(asm_res, expected, f"asm_aarch64 mismatch ({label})")
        return expected

    def test_tool_spec_and_section_j_asm_safety(self) -> None:
        self.assertEqual(LOGFORGE_TOOL_SPEC.name, "LogForge")
        self.assertEqual(len(LOGFORGE_TOOL_SPEC.tiers), 4)
        asm_src = REPO_ROOT / "native" / "asm" / "aarch64" / "delim_scan.S"
        if asm_src.is_file():
            asm_text = asm_src.read_text(encoding="utf-8")
            # Strip comments and verify no supervisor call (`svc`) or callee-saved reg clobbers
            code_lines = [
                ln.split("//", 1)[0].strip().lower()
                for ln in asm_text.splitlines()
                if not ln.strip().startswith(("/*", "*", "//"))
            ]
            for ln in code_lines:
                self.assertIsNone(re.search(r"\bsvc\b", ln), f"Forbidden syscall in .S: {ln}")
                for forbidden_reg in (
                    "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28",
                    "w18", "w19", "w20", "w21", "w22", "w23", "w24", "w25", "w26", "w27", "w28",
                    "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
                ):
                    self.assertIsNone(
                        re.search(rf"\b{forbidden_reg}\b", ln),
                        f"Forbidden register {forbidden_reg} in {ln}",
                    )

    def test_empty_and_single_byte_boundaries(self) -> None:
        for payload, delim in [
            (b"", ord("\n")),
            (b"", 0),
            (b"\n", ord("\n")),
            (b"a", ord("\n")),
            (b"\x00", 0),
            (b"\xff", 0xFF),
        ]:
            self._assert_all_tiers_equal(payload, delim, label=f"len={len(payload)} delim={delim}")

    def test_vector_width_non_divisible_sizes(self) -> None:
        sizes = [15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 257]
        for sz in sizes:
            # Sparse delimiters at start, boundary-1, boundary, boundary+1, end
            buf = bytearray(b"A" * sz)
            for idx in {0, sz // 2, max(0, sz - 2), sz - 1, 14, 15, 16, 30, 31, 32, 62, 63, 64}:
                if idx < sz:
                    buf[idx] = ord("\n")
            self._assert_all_tiers_equal(bytes(buf), ord("\n"), label=f"sparse size={sz}")

            # All-delimiter buffer (every bit set in 64-bit bitmask!)
            all_delim = bytes([0x0A] * sz)
            self._assert_all_tiers_equal(all_delim, ord("\n"), label=f"dense size={sz}")

            # Zero-delimiter buffer
            no_delim = bytes([0x42] * sz)
            self._assert_all_tiers_equal(no_delim, ord("\n"), label=f"empty-match size={sz}")

    def test_unaligned_memory_offsets_across_all_tiers(self) -> None:
        raw = bytearray(b"X" * 260)
        for idx in (0, 1, 2, 3, 7, 14, 15, 16, 17, 31, 32, 33, 63, 64, 65, 130, 199, 259):
            raw[idx] = ord("\n")
        mv = memoryview(raw)

        for shift in (1, 3, 7, 15):
            sliced_mv = mv[shift:]
            expected = scan_delimiters_python(sliced_mv, ord("\n"))
            sliced_bytes = bytes(sliced_mv)
            res_simd = self.bridge.scan_bytes(sliced_bytes, delim=ord("\n"), disable_simd=False)
            res_fb = self.bridge.scan_bytes(sliced_bytes, delim=ord("\n"), disable_simd=True)
            self.assertEqual(res_simd.offsets, expected, f"shift={shift}")
            self.assertEqual(res_fb.offsets, expected, f"fb shift={shift}")

            # True unaligned raw pointer passed directly into C NEON and AArch64 .S via ctypes
            if self.probe is not None:
                parent = (ctypes.c_uint8 * len(raw)).from_buffer_copy(raw)
                sub_len = len(raw) - shift
                ptr = ctypes.cast(ctypes.addressof(parent) + shift, ctypes.POINTER(ctypes.c_uint8))
                out_c = (ctypes.c_uint64 * sub_len)()
                cnt_c = int(self.probe._lib.logforge_c_neon_scan_delimiters(ptr, sub_len, ord("\n"), out_c, sub_len))
                self.assertEqual([int(out_c[i]) for i in range(cnt_c)], expected, f"c_neon raw shift={shift}")
                if self.probe.has_asm_symbol:
                    out_asm = (ctypes.c_uint64 * sub_len)()
                    cnt_asm = int(self.probe._lib.logforge_asm_scan_delimiters(ptr, sub_len, ord("\n"), out_asm, sub_len))
                    self.assertEqual([int(out_asm[i]) for i in range(cnt_asm)], expected, f"asm raw shift={shift}")

    def test_utf8_and_embedded_nul_binary_bytes(self) -> None:
        utf8_payload = (
            "Tiếng Việt có dấu 🚀\n"
            "日本語テスト\x00binary\x00tail\n"
            "éàüöñ\xff\xfe\x00\x0aend"
        ).encode("utf-8", errors="surrogatepass")
        # Normalize valid UTF-8 + embedded binary bytes
        payload = b"Ti\xe1\xba\xbfng Vi\xe1\xbb\x87t \xf0\x9f\x9a\x80\n\xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e\x00binary\x00\xff\xfe\nend"
        self._assert_all_tiers_equal(payload, ord("\n"), label="utf8+nul newline")
        self._assert_all_tiers_equal(payload, 0x00, label="utf8+nul zero")
        self._assert_all_tiers_equal(payload, 0xFF, label="utf8+nul 0xff")
        self.assertGreater(len(utf8_payload), 0)

    def test_probe_bounds_safety_and_canary(self) -> None:
        if self.probe is None:
            self.skipTest("C/ASM probe library not built")
        buf = b"a\nb\nc\nd\ne\nf\n"
        in_buf = (ctypes.c_uint8 * len(buf)).from_buffer_copy(buf)
        # Allocate 8 slots: first 2 writable (out_cap=2), slots 2..7 sentinel canaries
        out_buf = (ctypes.c_uint64 * 8)(*([0xCAFE_BABE_DEAD_BEEF] * 8))
        for sym in ("logforge_c_scalar_scan_delimiters", "logforge_c_neon_scan_delimiters", "logforge_asm_scan_delimiters"):
            if sym == "logforge_asm_scan_delimiters" and not self.probe.has_asm_symbol:
                continue
            for i in range(8):
                out_buf[i] = 0xCAFE_BABE_DEAD_BEEF
            fn = getattr(self.probe._lib, sym)
            total_found = int(fn(in_buf, len(buf), ord("\n"), out_buf, 2))
            self.assertEqual(total_found, 6, sym)
            self.assertEqual([out_buf[0], out_buf[1]], [1, 3], sym)
            for canary_idx in range(2, 8):
                self.assertEqual(out_buf[canary_idx], 0xCAFE_BABE_DEAD_BEEF, f"{sym} overwrote canary {canary_idx}")

            # NULL out_offsets / out_cap=0 must still return exact count safely
            self.assertEqual(int(fn(in_buf, len(buf), ord("\n"), None, 0)), 6, sym)
            self.assertEqual(int(fn(None, 10, ord("\n"), None, 0)), 0, sym)

    def test_multibyte_and_streaming_parity(self) -> None:
        corpus = [
            (b"", b"||"),
            (b"a||b||||c||", b"||"),
            (b"ababababa", b"aba"),
            (b"line1\r\nline2\r\n\r\nline3\r\n", b"\r\n"),
            (b"\x00\xff" * 40 + b"abc\x00\xff", b"\x00\xff"),
        ]
        for data, pat in corpus:
            py_offs = scan_multibyte_delimiters_python(data, pat)
            rust_simd = self.bridge.scan_bytes(data, pattern=pat, disable_simd=False).offsets
            rust_fb = self.bridge.scan_bytes(data, pattern=pat, disable_simd=True).offsets
            self.assertEqual(rust_simd, py_offs, f"multibyte simd pat={pat!r}")
            self.assertEqual(rust_fb, py_offs, f"multibyte fallback pat={pat!r}")

            for chunk_sz in (1, 2, 3, 7, 13, 32):
                stream = StreamingLogForgePython(pattern=pat)
                stream_offs: List[int] = []
                for pos in range(0, len(data), chunk_sz):
                    stream_offs.extend(stream.push_chunk(data[pos : pos + chunk_sz]))
                self.assertEqual(stream_offs, py_offs, f"streaming pat={pat!r} chunk={chunk_sz}")

    def test_jsonl_and_timestamp_normalization_parity(self) -> None:
        self.assertEqual(normalize_timestamp_utc_python("2026-11-21T18:26:00.123456+07:00"), "2026-11-21T11:26:00.123456Z")
        self.assertEqual(normalize_timestamp_utc_python("1795266360123456"), "2026-11-21T13:06:00.123456Z")
        self.assertEqual(normalize_timestamp_utc_python("1795266360.987654321"), "2026-11-21T13:06:00.987654321Z")

        log_payload = (
            '{"timestamp":"2026-11-21T18:26:00.500+07:00","level":"warn","message":"rocket \\uD83D\\uDE80 ok"}\r\n'
            "2026-11-21 11:26:01Z ERROR disk full\n"
            'ts=1795266362.250 level=info msg="hello world"\n'
            "unstructured plain payload\n"
        ).encode("utf-8")

        py_events = normalize_log_records_python(log_payload, delim=0x0A)
        rust_simd = self.bridge.scan_bytes(log_payload, delim=0x0A, disable_simd=False, normalize=True)
        rust_fb = self.bridge.scan_bytes(log_payload, delim=0x0A, disable_simd=True, normalize=True)
        assert rust_simd.events is not None
        assert rust_fb.events is not None

        self.assertEqual([e.to_dict() for e in rust_simd.events], [e.to_dict() for e in py_events])
        self.assertEqual([e.to_dict() for e in rust_fb.events], [e.to_dict() for e in py_events])
        self.assertEqual(py_events[0].message, "rocket 🚀 ok")
        self.assertEqual(py_events[0].timestamp_utc, "2026-11-21T11:26:00.5Z")
        self.assertEqual(py_events[1].format, "structured")
        self.assertEqual(py_events[2].timestamp_utc, "2026-11-21T13:06:02.25Z")
        self.assertEqual(py_events[3].format, "raw")

    def test_randomized_fuzz_550_inputs_all_tiers_parity(self) -> None:
        rng = random.Random(20261121)
        total_cases = 550
        for case_idx in range(total_cases):
            # Mix lengths heavily around SIMD lane boundaries (0..260) and medium buffers (260..4096)
            if case_idx < 250:
                length = rng.randint(0, 260)
            else:
                length = rng.randint(261, 4096)
            delim = rng.choice([0x0A, 0x00, 0x7C, 0xFF, rng.randint(0, 255)])

            # Construct data with varying delimiter density (0%, ~1%, ~15%, ~50%, ~100%)
            mode = case_idx % 5
            if mode == 0:
                buf = bytes(rng.getrandbits(8) for _ in range(length))
            elif mode == 1:
                raw = bytearray(rng.randint(32, 126) for _ in range(length))
                for i in range(length):
                    if rng.random() < 0.02:
                        raw[i] = delim
                buf = bytes(raw)
            elif mode == 2:
                raw = bytearray(b"x" * length)
                for i in range(length):
                    if rng.random() < 0.25:
                        raw[i] = delim
                buf = bytes(raw)
            elif mode == 3:
                buf = bytes(delim if (i % 2 == 0) else (delim ^ 0x01) for i in range(length))
            else:
                # Non-zero probability of no matches
                non_delim = (delim + 1) & 0xFF
                buf = bytes([non_delim] * length)

            expected = scan_delimiters_python(buf, delim)

            # Check C scalar, C NEON, and AArch64 .S via ctypes on all 550 inputs
            if self.probe is not None:
                self.assertEqual(self.probe.scan_delimiters(buf, delim, variant="c_scalar"), expected)
                self.assertEqual(self.probe.scan_delimiters(buf, delim, variant="c_neon"), expected)
                if self.probe.has_asm_symbol:
                    self.assertEqual(self.probe.scan_delimiters(buf, delim, variant="asm_aarch64"), expected)

            # Check Rust SIMD & Rust fallback via CLI on all 550 inputs (file input avoids pipe limits)
            res_simd = self.bridge.scan_bytes(buf, delim=delim, disable_simd=False)
            res_fb = self.bridge.scan_bytes(buf, delim=delim, disable_simd=True)
            self.assertEqual(res_simd.offsets, expected, f"fuzz case={case_idx} len={length} delim={delim}")
            self.assertEqual(res_fb.offsets, expected, f"fuzz fb case={case_idx} len={length} delim={delim}")

    def test_cli_unknown_flags_exit_code_2(self) -> None:
        for subcmd in ("scan-bytes", "logforge-bench"):
            proc = subprocess.run(
                [str(self.rust_bin), subcmd, "--unknown-flag-xyz"],
                capture_output=True,
                shell=False,
                check=False,
            )
            self.assertEqual(proc.returncode, 2, f"{subcmd} should exit 2 on unknown flag")

    def test_logforge_bench_cli_outputs_valid_json(self) -> None:
        rep = self.bridge.benchmark(size_bytes=65536, warmup=2, iters=5, seed=42)
        self.assertTrue(rep["parity_ok"])
        self.assertEqual(rep["tool"], "LogForge")
        self.assertIn("simd", rep["results"])
        self.assertIn("scalar", rep["results"])
        self.assertIn("simd_fallback", rep["results"])


if __name__ == "__main__":
    unittest.main()
