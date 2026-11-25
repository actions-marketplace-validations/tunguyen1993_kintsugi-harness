"""Tests for Build #3 ARM64/NEON Assembly & Portable C99 Native Forge (`asm_native_forge`)."""

from __future__ import annotations

import os
import platform
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

from kintsugi.forge.asm_native_forge import (
    KINTSUGI_ASM_ABI_MAGIC,
    KINTSUGI_ASM_ABI_VERSION,
    AsmBuildManifest,
    AsmKernelSpec,
    AsmNativeForge,
    build_crc32c_fnv64_kernel_spec,
    build_delim_scan_kernel_spec,
    crc32c_fnv64_python,
    delim_scan_python,
    detect_host_arch,
    scan_asm_source_safety,
)


class TestAsmNativeForge(unittest.TestCase):
    """Comprehensive tests for static gating, ARM64/NEON kernels, reproducibility, and speed."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="kintsugi_asm_test_")
        self.ws = Path(self._tmp.name).resolve()
        self.forge = AsmNativeForge(self.ws)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_static_safety_rejects_malicious_syscalls_apis_and_unknown_abi(self) -> None:
        base_header = (
            '#include <stdint.h>\n'
            'const char *kintsugi_asm_abi_version(void) { return "KINTSUGI_ASM_ABI_V1"; }\n'
        )
        bad_sources = {
            "inline_svc_syscall": (
                base_header
                + 'int32_t bad_fn(void) { __asm__ volatile("svc #0"); return 0; }\n',
                "FORBIDDEN_INLINE_ASM_SYSCALL_OR_PRIV",
            ),
            "raw_inst_opcode_smuggle": (
                base_header
                + 'int32_t bad_fn(void) { __asm__ volatile(".inst 0xd4000001"); return 0; }\n',
                "FORBIDDEN_INLINE_ASM_SYSCALL_OR_PRIV",
            ),
            "system_call": (
                base_header
                + 'int32_t bad_fn(void) { return system("id"); }\n',
                "FORBIDDEN_PROCESS_EXEC_CALL",
            ),
            "popen_execve_calls": (
                base_header
                + 'int32_t bad_fn(void) { popen("ls", "r"); return execve("/bin/sh", 0, 0); }\n',
                "FORBIDDEN_PROCESS_EXEC_CALL",
            ),
            "dlopen_call": (
                base_header
                + 'void *bad_fn(void) { return dlopen("libc.dylib", 1); }\n',
                "FORBIDDEN_DYNAMIC_LOAD_CALL",
            ),
            "mmap_and_socket": (
                base_header
                + 'int32_t bad_fn(void) { mmap(0, 4096, 7, 0, -1, 0); return socket(2, 1, 0); }\n',
                "FORBIDDEN_MEMORY_OR_SYSCALL_API",
            ),
            "unsafe_format_sink": (
                base_header
                + 'void bad_fn(char *dst, const char *src) { sprintf(dst, src); }\n',
                "FORBIDDEN_UNSAFE_STRING_OR_FORMAT_SINK",
            ),
        }

        for label, (malicious_src, expected_rule) in bad_sources.items():
            ok, reasons = scan_asm_source_safety(malicious_src, allow_asm=True)
            self.assertFalse(ok, msg=f"{label} unexpectedly passed static safety")
            self.assertIn(expected_rule, reasons, msg=f"{label} reasons={reasons}")

            bad_spec = AsmKernelSpec(
                kernel_id=f"asm.bad.{label}",
                version="1.0.0",
                abi_version=KINTSUGI_ASM_ABI_VERSION,
                description="Rejected test kernel",
                source_code=malicious_src,
                oracle_fn=lambda b: b,
                exported_symbols=("kintsugi_asm_abi_version",),
                boundary_and_fuzz_cases=(),
                benchmark_payload=b"x",
            )
            res = self.forge.forge_kernel(bad_spec)
            self.assertFalse(res.verified)
            self.assertFalse(res.safety_ok)
            self.assertIn("STATIC_SAFETY_REJECTED", res.reason)
            self.assertIsNone(res.binary_path)

        # Reject unknown ABI version before invoking compiler
        ok_abi, abi_reasons = scan_asm_source_safety(
            base_header,
            allow_asm=True,
            abi_version="KINTSUGI_ASM_ABI_V999",
        )
        self.assertFalse(ok_abi)
        self.assertIn("UNSUPPORTED_ASM_ABI_VERSION", abi_reasons)

        bad_abi_spec = AsmKernelSpec(
            kernel_id="asm.bad.unknown_abi",
            version="1.0.0",
            abi_version="KINTSUGI_ASM_ABI_V999",
            description="Unknown ABI rejection test",
            source_code=build_delim_scan_kernel_spec(benchmark_size_bytes=64).source_code,
            oracle_fn=delim_scan_python,
            exported_symbols=("kintsugi_asm_abi_version",),
            boundary_and_fuzz_cases=(),
            benchmark_payload=b"a\nb\n",
        )
        abi_res = self.forge.forge_kernel(bad_abi_spec)
        self.assertFalse(abi_res.verified)
        self.assertFalse(abi_res.safety_ok)
        self.assertIn("UNSUPPORTED_ASM_ABI_VERSION", abi_res.reason)

    def test_delim_scan_v1_neon_and_scalar_200_fuzz_parity_and_1mib_speedup(self) -> None:
        spec = build_delim_scan_kernel_spec(fuzz_count=200, benchmark_size_bytes=1024 * 1024)
        self.assertGreaterEqual(len(spec.boundary_and_fuzz_cases), 200)

        res = self.forge.forge_kernel(spec, warmup_iterations=2, measured_iterations=7)
        self.assertTrue(res.verified, msg=f"Forge failed: {res.reason}")
        self.assertTrue(res.safety_ok)
        self.assertIsNotNone(res.manifest)
        self.assertIsNotNone(res.binary_path)
        self.assertIsNotNone(res.differential_report)
        self.assertIsNotNone(res.benchmark_report)

        diff = res.differential_report
        assert diff is not None
        self.assertTrue(diff.passed)
        self.assertGreaterEqual(diff.total_cases, 200)
        self.assertEqual(diff.failed_cases, 0)
        self.assertEqual(diff.abi_version_reported, KINTSUGI_ASM_ABI_VERSION)

        if detect_host_arch() == "aarch64":
            self.assertEqual(diff.backend_reported, "aarch64_neon_inline_asm")

        bench = res.benchmark_report
        assert bench is not None
        self.assertEqual(bench.payload_bytes, 1024 * 1024)
        self.assertEqual(bench.abi_version, KINTSUGI_ASM_ABI_VERSION)
        self.assertGreater(
            bench.speedup_decimal,
            Decimal("10.0000"),
            msg=f"Expected >10x speedup for delim_scan, got {bench.speedup_decimal}x",
        )
        self.assertGreater(bench.kernel_only_throughput_gbps, Decimal("0.5000"))

        # Verify loaded kernel handles embedded NUL bytes and unaligned tail lengths directly
        assert res.manifest is not None and res.binary_path is not None
        loaded = self.forge.load_verified_kernel(
            res.binary_path,
            expected_sha256=res.manifest.binary_sha256,
            expected_kernel_id=spec.kernel_id,
            expected_abi_version=KINTSUGI_ASM_ABI_VERSION,
        )
        self.assertEqual(loaded.abi_magic, KINTSUGI_ASM_ABI_MAGIC)
        nul_sample = b"\x00abc\x00" + (b"z" * 64) + b"\x00tail\x00"
        self.assertEqual(loaded.delim_scan(nul_sample, 0), delim_scan_python(nul_sample, 0))

        # Also verify portable C99 scalar fallback compiles & achieves 100% parity
        scalar_forge = AsmNativeForge(self.ws / "scalar_ws", force_scalar=True)
        scalar_spec = build_delim_scan_kernel_spec(fuzz_count=200, benchmark_size_bytes=4096)
        scalar_res = scalar_forge.forge_kernel(scalar_spec, warmup_iterations=1, measured_iterations=3)
        self.assertTrue(scalar_res.verified)
        assert scalar_res.differential_report is not None
        self.assertEqual(scalar_res.differential_report.backend_reported, "portable_c99_scalar")
        self.assertEqual(scalar_res.differential_report.parity_digest, diff.parity_digest)

    def test_crc32c_fnv64_v1_arm64_200_fuzz_parity_and_1mib_speedup(self) -> None:
        spec = build_crc32c_fnv64_kernel_spec(fuzz_count=200, benchmark_size_bytes=1024 * 1024)
        self.assertGreaterEqual(len(spec.boundary_and_fuzz_cases), 200)

        res = self.forge.forge_kernel(spec, warmup_iterations=2, measured_iterations=7)
        self.assertTrue(res.verified, msg=f"Forge failed: {res.reason}")
        self.assertIsNotNone(res.differential_report)
        self.assertIsNotNone(res.benchmark_report)

        diff = res.differential_report
        assert diff is not None
        self.assertTrue(diff.passed)
        self.assertGreaterEqual(diff.total_cases, 200)
        self.assertEqual(diff.failed_cases, 0)
        self.assertEqual(diff.abi_version_reported, KINTSUGI_ASM_ABI_VERSION)

        if detect_host_arch() == "aarch64" and platform.system() == "Darwin":
            self.assertEqual(diff.backend_reported, "aarch64_crc32_inline_asm")

        bench = res.benchmark_report
        assert bench is not None
        self.assertEqual(bench.payload_bytes, 1024 * 1024)
        self.assertGreater(
            bench.speedup_decimal,
            Decimal("10.0000"),
            msg=f"Expected >10x speedup for crc32c_fnv64, got {bench.speedup_decimal}x",
        )

        # Verify canonical RFC 3720 Castagnoli vector & portable scalar parity
        assert res.manifest is not None and res.binary_path is not None
        loaded = self.forge.load_verified_kernel(
            res.binary_path,
            expected_sha256=res.manifest.binary_sha256,
            expected_kernel_id=spec.kernel_id,
        )
        rfc_out = loaded.crc32c_fnv64(b"123456789")
        self.assertEqual(rfc_out["crc32c"], 0xE3069283)
        self.assertEqual(rfc_out, crc32c_fnv64_python(b"123456789"))

        scalar_forge = AsmNativeForge(self.ws / "scalar_crc_ws", force_scalar=True)
        scalar_spec = build_crc32c_fnv64_kernel_spec(fuzz_count=200, benchmark_size_bytes=4096)
        scalar_res = scalar_forge.forge_kernel(scalar_spec, warmup_iterations=1, measured_iterations=3)
        self.assertTrue(scalar_res.verified)
        assert scalar_res.differential_report is not None
        self.assertEqual(scalar_res.differential_report.backend_reported, "portable_c99_scalar")
        self.assertEqual(scalar_res.differential_report.parity_digest, diff.parity_digest)

    def test_reproducible_build_manifest_sha256_determinism_and_nofollow_pinning(self) -> None:
        ws_a = self.ws / "build_a"
        ws_b = self.ws / "build_b"
        forge_a = AsmNativeForge(ws_a)
        forge_b = AsmNativeForge(ws_b)

        for spec in (
            build_delim_scan_kernel_spec(fuzz_count=200, benchmark_size_bytes=4096),
            build_crc32c_fnv64_kernel_spec(fuzz_count=200, benchmark_size_bytes=4096),
        ):
            bin_a, man_a, mpath_a = forge_a.compile_kernel(spec)
            bin_b, man_b, mpath_b = forge_b.compile_kernel(spec)

            self.assertEqual(man_a.source_sha256, man_b.source_sha256)
            self.assertEqual(man_a.binary_sha256, man_b.binary_sha256)
            self.assertEqual(man_a.manifest_sha256, man_b.manifest_sha256)
            self.assertEqual(
                AsmBuildManifest.load_verified(mpath_a).manifest_sha256,
                AsmBuildManifest.load_verified(mpath_b).manifest_sha256,
            )

            # Tampered SHA-256, ABI mismatch, tampered manifest, or symlink binary must be rejected
            with self.assertRaises(PermissionError):
                forge_a.load_verified_kernel(
                    bin_a,
                    expected_sha256="sha256:" + ("0" * 64),
                    expected_kernel_id=spec.kernel_id,
                )

            with self.assertRaises(ValueError):
                forge_a.load_verified_kernel(
                    bin_a,
                    expected_sha256=man_a.binary_sha256,
                    expected_kernel_id="asm.wrong_kernel.v1",
                )

            with self.assertRaises(ValueError):
                forge_a.load_verified_kernel(
                    bin_a,
                    expected_sha256=man_a.binary_sha256,
                    expected_kernel_id=spec.kernel_id,
                    expected_abi_version="KINTSUGI_ASM_ABI_V2",
                )

            tampered_mpath = ws_a / f"tampered_{spec.kernel_id}.json"
            tampered_mpath.write_text(
                mpath_a.read_text(encoding="utf-8").replace(man_a.manifest_sha256, "sha256:" + ("f" * 64)),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                AsmBuildManifest.load_verified(tampered_mpath)

            symlink_bin = ws_a / f"evil_link_{spec.kernel_id}.dylib"
            os.symlink(str(bin_a), str(symlink_bin))
            with self.assertRaises(PermissionError):
                forge_a.load_verified_kernel(
                    symlink_bin,
                    expected_sha256=man_a.binary_sha256,
                    expected_kernel_id=spec.kernel_id,
                )


if __name__ == "__main__":
    unittest.main()
