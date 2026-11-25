/*
 * kintsugi.h — Verified C99 / C++ ABI v1 Header for `kintsugi_core` (`libkintsugi_core`).
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Concurrency, Memory, Capability & Error Contracts:
 *   1. Thread-Safe & Reentrant: Every entrypoint has zero process-global mutable state, zero
 *      filesystem I/O, zero network I/O, and is safe to invoke concurrently across OS threads.
 *      The only state is a per-thread, single-slot, one-shot memo (input <= 256 KiB, JSON <= 256 KiB)
 *      that lets the two-call size-probe pattern skip re-scanning; it never changes observable results.
 *   2. Unwind-Protected Boundary: `Cargo.toml` pins `panic = "unwind"` in `[profile.release]`, so every
 *      Rust `extern "C"` function's `catch_unwind` always intercepts panics at the FFI boundary and
 *      returns `KINTSUGI_FFI_ERR_PANIC` (-99); no panic ever unwinds into C/C++ frames.
 *   3. Pointer Ownership & Validation Contract: Caller owns pointer validity, lifetime, and
 *      writability across the call duration. FFI enforces non-null checks, `<= INTPTR_MAX`
 *      (`isize::MAX`) bounds, natural `size_t` alignment on `output_len`, and strict non-overlap
 *      between all input buffers, output buffers, and `output_len` (`KINTSUGI_FFI_ERR_INVALID_ARG`
 *      (-4) on overlap/misalignment; `KINTSUGI_FFI_ERR_NULL_PTR` (-1) on NULL). No heap pointers
 *      cross the FFI boundary.
 *   4. Compile-Time vs Runtime Capability Masks (`KINTSUGI_FEAT_*`):
 *      - `kintsugi_abi_compiled_features_v1()` returns compile-time capability bits:
 *        * `KINTSUGI_FEAT_SIMD` (1u << 0): static `target_feature` (`neon` on AArch64 / `avx2` on x86_64).
 *        * `KINTSUGI_FEAT_SHA256` (1u << 1): `kintsugi_sha256_v1` FIPS 180-4 API compiled & unconditionally
 *          available (software scalar baseline + optional hardware acceleration).
 *        * `KINTSUGI_FEAT_RULE_IR` (1u << 2): 1-to-1 Cargo `feature = "rule-ir"` (`kintsugi_rule_ir_eval_v1`).
 *        * `KINTSUGI_FEAT_SHADOW_ARM_C` (1u << 3): flow-sensitive Python AST/taint Arm-C rules (`KC-C01..KC-C05`)
 *          compiled in `kintsugi_core::parsers`. `kintsugi_scan_buffer_v1` runs them automatically, in addition
 *          to the 36-rule `KS-*` baseline, whenever the effective `lang` is `"python"` (including the empty-`lang`
 *          default); no separate v1 C-ABI entrypoint or opt-in flag is required.
 *        * `KINTSUGI_FEAT_SARIF` (1u << 4): 1-to-1 Cargo `feature = "sarif"` (`render_findings_sarif` compiled).
 *        * `KINTSUGI_FEAT_AUDIT` (1u << 5): 1-to-1 Cargo `feature = "audit"`.
 *        * `KINTSUGI_FEAT_LOGFORGE` (1u << 6): 1-to-1 Cargo `feature = "logforge"`.
 *        * `KINTSUGI_FEAT_HW_SHA256` (1u << 7): static `target_feature` (`sha2` / `sha`) hardware SHA-256.
 *      - `kintsugi_abi_features_v1()` ORs runtime-detected CPU capabilities onto the compile-time mask
 *        (`compiled_mask | runtime_cpu_mask`), setting `KINTSUGI_FEAT_SIMD` when runtime NEON/AVX2 is active
 *        and `KINTSUGI_FEAT_HW_SHA256` when CPU hardware SHA-256 (`FEAT_SHA2` on AArch64 / `SHA-NI` on x86_64)
 *        is active at runtime.
 *   5. `output_len` Error-Path & Two-Call Size-Probe Contract:
 *      - On any validation or execution error (`rc < 0` other than `KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL`),
 *        if `output_len` is valid, aligned, non-null, and non-overlapping, `*output_len` is explicitly
 *        set to `0`.
 *      - On `KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL` (-3) or size-probe (`output == NULL` and
 *        `output_capacity == 0`), `*output_len` is set to the required payload byte length
 *        (excluding any trailing NUL). When `output_capacity > *output_len`, a trailing NUL (`'\0'`)
 *        is written at `output[*output_len]`.
 *      - `kintsugi_sha256_v1` writes a fixed 64-byte hex digest and requires `out_cap >= 64` directly.
 */

#ifndef KINTSUGI_H
#define KINTSUGI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Verified C-ABI Version */
#define KINTSUGI_ABI_VERSION              1u

/* Status & Error Return Codes */
#define KINTSUGI_FFI_OK                   0
#define KINTSUGI_FFI_ERR_NULL_PTR        (-1)
#define KINTSUGI_FFI_ERR_INVALID_UTF8    (-2)
#define KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL (-3)
#define KINTSUGI_FFI_ERR_INVALID_ARG     (-4)
#define KINTSUGI_FFI_ERR_RULE_INVALID    (-5)
#define KINTSUGI_FFI_ERR_OVERFLOW        (-6)
#define KINTSUGI_FFI_ERR_INTERNAL        (-7)
#define KINTSUGI_FFI_ERR_PANIC           (-99)

/* Hard DoS Input & Serialization Ceilings */
#define KINTSUGI_MAX_FFI_INPUT_BYTES      ((size_t)(16u * 1024u * 1024u))
#define KINTSUGI_MAX_FFI_RULE_BYTES       ((size_t)(1024u * 1024u))
#define KINTSUGI_MAX_FFI_LANG_BYTES       ((size_t)64u)
#define KINTSUGI_MAX_REPO_FINDINGS        ((size_t)10000u)

/*
 * Capability Bitflags returned by `kintsugi_abi_compiled_features_v1()` / `kintsugi_abi_features_v1()`:
 *   - KINTSUGI_FEAT_SIMD         : NEON/AVX2 byte-scanner SIMD (compile-time target_feature or runtime active)
 *   - KINTSUGI_FEAT_SHA256       : `kintsugi_sha256_v1` API compiled & available (software + hardware)
 *   - KINTSUGI_FEAT_RULE_IR      : Cargo `cfg!(feature = "rule-ir")` (`kintsugi_rule_ir_eval_v1` enabled)
 *   - KINTSUGI_FEAT_SHADOW_ARM_C : Python Arm-C rules (`KC-C01..KC-C05`), auto-run by `kintsugi_scan_buffer_v1` for `lang == "python"`
 *   - KINTSUGI_FEAT_SARIF        : Cargo `cfg!(feature = "sarif")` (OASIS SARIF 2.1.0 formatter compiled)
 *   - KINTSUGI_FEAT_AUDIT        : Cargo `cfg!(feature = "audit")` (`PreToolUse`, S3 seam & memory auditors)
 *   - KINTSUGI_FEAT_LOGFORGE     : Cargo `cfg!(feature = "logforge")` (LogForge normalizer & benchmarks)
 *   - KINTSUGI_FEAT_HW_SHA256    : CPU hardware SHA-256 (`FEAT_SHA2` on AArch64 / `SHA-NI` on x86_64) active
 */
#define KINTSUGI_FEAT_SIMD                (1u << 0)
#define KINTSUGI_FEAT_SHA256              (1u << 1)
#define KINTSUGI_FEAT_RULE_IR             (1u << 2)
#define KINTSUGI_FEAT_SHADOW_ARM_C        (1u << 3)
#define KINTSUGI_FEAT_SARIF               (1u << 4)
#define KINTSUGI_FEAT_AUDIT               (1u << 5)
#define KINTSUGI_FEAT_LOGFORGE            (1u << 6)
#define KINTSUGI_FEAT_HW_SHA256           (1u << 7)

/**
 * Return the verified C-ABI version (`1`). Returns `0` only on internal fault.
 */
uint32_t kintsugi_abi_version(void);

/**
 * Return compile-time capability flags: baseline API/parser bits (`KINTSUGI_FEAT_SHA256`,
 * `KINTSUGI_FEAT_SHADOW_ARM_C`), 1-to-1 Cargo features (`KINTSUGI_FEAT_RULE_IR`,
 * `KINTSUGI_FEAT_SARIF`, `KINTSUGI_FEAT_AUDIT`, `KINTSUGI_FEAT_LOGFORGE`), and static
 * `target_feature` flags (`KINTSUGI_FEAT_SIMD`, `KINTSUGI_FEAT_HW_SHA256`).
 */
uint32_t kintsugi_abi_compiled_features_v1(void);

/**
 * Return `kintsugi_abi_compiled_features_v1() | runtime_cpu_mask`, adding runtime-detected
 * CPU SIMD (`KINTSUGI_FEAT_SIMD`: NEON/AVX2) and hardware SHA-256 (`KINTSUGI_FEAT_HW_SHA256`:
 * AArch64 `FEAT_SHA2` / x86_64 `SHA-NI`) when active on the current host CPU.
 */
uint32_t kintsugi_abi_features_v1(void);

/**
 * Compute FIPS 180-4 SHA-256 over `[input, input + input_len)` into `out_hex`.
 *
 * - Rejects `input_len > KINTSUGI_MAX_FFI_INPUT_BYTES` with `KINTSUGI_FFI_ERR_OVERFLOW` (-6).
 * - `input` may be `NULL` iff `input_len == 0`.
 * - Requires non-null `out_hex` with `out_cap >= 64` (`KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL` (-3)
 *   when `out_cap < 64`; `out_hex` must not overlap `input`).
 * - Writes 64 lowercase ASCII hex bytes; writes trailing NUL at `out_hex[64]` when `out_cap >= 65`.
 */
int32_t kintsugi_sha256_v1(
    const uint8_t *input,
    size_t input_len,
    uint8_t *out_hex,
    size_t out_cap
);

/**
 * Scan an in-memory UTF-8 source buffer against all built-in rules (zero FS/network I/O).
 *
 * - Bounded in-memory allocation: never allocates `> KINTSUGI_MAX_REPO_FINDINGS` (10,000) findings
 *   prior to JSON serialization, reporting `"truncated": true|false`.
 * - On error (`rc < 0` other than `-3`), sets `*output_len = 0` when `output_len` is valid.
 * - On `KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL` (-3) or size-probe (`output = NULL, output_capacity = 0`),
 *   sets `*output_len` to required payload byte length (excluding NUL).
 */
int32_t kintsugi_scan_buffer_v1(
    const uint8_t *input,
    size_t input_len,
    const uint8_t *lang_ptr,
    size_t lang_len,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_len
);

/**
 * Evaluate a canonical `RuleIR/1` JSON payload against an in-memory UTF-8 buffer (zero FS/network I/O).
 *
 * - Returns `KINTSUGI_FFI_ERR_INTERNAL` (-7) when compiled without the `rule-ir` Cargo feature.
 * - Returns `KINTSUGI_FFI_ERR_RULE_INVALID` (-5) when `rule_json_ptr` fails `RuleIR/1` validation.
 * - On error (`rc < 0` other than `-3`), sets `*output_len = 0` when `output_len` is valid.
 * - Probe required capacity by passing `output = NULL, output_capacity = 0` and valid `output_len`.
 */
int32_t kintsugi_rule_ir_eval_v1(
    const uint8_t *rule_json_ptr,
    size_t rule_json_len,
    const uint8_t *code_ptr,
    size_t code_len,
    const uint8_t *lang_ptr,
    size_t lang_len,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_len
);

/** Alias of `kintsugi_rule_ir_eval_v1` with identical ABI, capability, and `output_len` contracts. */
int32_t kintsugi_eval_rule_ir_v1(
    const uint8_t *rule_json_ptr,
    size_t rule_json_len,
    const uint8_t *code_ptr,
    size_t code_len,
    const uint8_t *lang_ptr,
    size_t lang_len,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_len
);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* KINTSUGI_H */
