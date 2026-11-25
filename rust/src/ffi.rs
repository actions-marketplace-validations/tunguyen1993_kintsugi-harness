//! Verified C-ABI FFI Surface (`kintsugi_core::ffi`, ABI v1).
//!
//! Safety, Capability & `output_len` Contracts:
//! 1. Pointer Ownership & Range Validation: Caller owns pointer validity, lifetime, and writability;
//!    [`checked_slice_range`] and [`checked_mut_slice_range`] enforce non-null (when `len > 0`),
//!    `len <= isize::MAX`, non-wrapping `ptr + len <= usize::MAX`, natural `usize` alignment on
//!    `output_len`, and strict non-overlap between every mutable destination (`output`, `output_len`,
//!    `out_hex`) and every input/output range.
//! 2. Compile-Time vs Runtime Capabilities (`KINTSUGI_FEAT_*`):
//!    - `KINTSUGI_FEAT_SHA256` (`1 << 1`): `kintsugi_sha256_v1` API compiled & available (software + hardware).
//!    - `KINTSUGI_FEAT_HW_SHA256` (`1 << 7`): CPU hardware SHA-256 (`FEAT_SHA2` on AArch64 / `SHA-NI` on x86_64) active.
//!    - `KINTSUGI_FEAT_SHADOW_ARM_C` (`1 << 3`): Flow-sensitive Python shadow rules (`KC-C01..KC-C05`) compiled in `parsers`.
//!    - `KINTSUGI_FEAT_SARIF` (`1 << 4`): Driven 1-to-1 by `cfg!(feature = "sarif")`.
//!    - `KINTSUGI_FEAT_RULE_IR` (`1 << 2`), `KINTSUGI_FEAT_AUDIT` (`1 << 5`), `KINTSUGI_FEAT_LOGFORGE` (`1 << 6`):
//!      driven 1-to-1 by their respective Cargo features.
//!    - `KINTSUGI_FEAT_SIMD` (`1 << 0`): static `target_feature` (`neon`/`avx2`) in `kintsugi_abi_compiled_features_v1()`,
//!      or runtime-active SIMD byte scanner in `kintsugi_abi_features_v1()`.
//! 3. `output_len` Error-Path Contract: On validation/execution error (`rc < 0` other than
//!    `KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL`), whenever `output_len` is valid, aligned, non-null,
//!    and non-overlapping, `*output_len` is explicitly set to `0`. On `KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL`
//!    (`-3`) or size-probe (`output == NULL && output_capacity == 0`), `*output_len` is set to the
//!    required payload byte length (excluding trailing NUL).
//! 4. Bounded Allocation: `kintsugi_scan_buffer_v1` invokes `scan_text_buffer_bounded` so in-memory
//!    findings never exceed `MAX_REPO_FINDINGS` (`10,000`) prior to JSON serialization.

use std::cell::RefCell;
use std::mem::{align_of, size_of};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use crate::io_json::{JsonObj, ENGINE_VERSION};
use crate::kernels::sha256_hw::sha256_hex_into;
use crate::model::Severity;
use crate::output::render_findings_json_array;
use crate::rules::BUILTIN_RULES;
use crate::scanner::MAX_REPO_FINDINGS;

pub const KINTSUGI_ABI_VERSION: u32 = 1;

pub const KINTSUGI_FFI_OK: i32 = 0;
pub const KINTSUGI_FFI_ERR_NULL_PTR: i32 = -1;
pub const KINTSUGI_FFI_ERR_INVALID_UTF8: i32 = -2;
pub const KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL: i32 = -3;
pub const KINTSUGI_FFI_ERR_INVALID_ARG: i32 = -4;
pub const KINTSUGI_FFI_ERR_RULE_INVALID: i32 = -5;
pub const KINTSUGI_FFI_ERR_OVERFLOW: i32 = -6;
pub const KINTSUGI_FFI_ERR_INTERNAL: i32 = -7;
pub const KINTSUGI_FFI_ERR_PANIC: i32 = -99;

pub const KINTSUGI_MAX_FFI_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub const KINTSUGI_MAX_FFI_RULE_BYTES: usize = 1024 * 1024;
pub const KINTSUGI_MAX_FFI_LANG_BYTES: usize = 64;

/// NEON/AVX2 SIMD byte-scanner active (static `target_feature` or runtime CPU detection).
pub const FEAT_SIMD: u32 = 1 << 0;
/// `kintsugi_sha256_v1` FIPS 180-4 API compiled & available (software scalar + hardware).
pub const FEAT_SHA256: u32 = 1 << 1;
/// `RuleIR/1` evaluator compiled (`cfg!(feature = "rule-ir")`).
pub const FEAT_RULE_IR: u32 = 1 << 2;
/// Flow-sensitive Python AST/taint shadow rules (`KC-C01..KC-C05`) compiled in `parsers`.
pub const FEAT_SHADOW_ARM_C: u32 = 1 << 3;
/// OASIS SARIF 2.1.0 output formatter compiled (`cfg!(feature = "sarif")`).
pub const FEAT_SARIF: u32 = 1 << 4;
/// `PreToolUse` JIT hook, S3 seam auditor, and memory verifier compiled (`cfg!(feature = "audit")`).
pub const FEAT_AUDIT: u32 = 1 << 5;
/// LogForge normalizer & benchmarks compiled (`cfg!(feature = "logforge")`).
pub const FEAT_LOGFORGE: u32 = 1 << 6;
/// CPU hardware SHA-256 (`FEAT_SHA2` on AArch64 / `SHA-NI` on x86_64) active.
pub const FEAT_HW_SHA256: u32 = 1 << 7;

pub const KINTSUGI_FEAT_SIMD: u32 = FEAT_SIMD;
pub const KINTSUGI_FEAT_SHA256: u32 = FEAT_SHA256;
pub const KINTSUGI_FEAT_RULE_IR: u32 = FEAT_RULE_IR;
pub const KINTSUGI_FEAT_SHADOW_ARM_C: u32 = FEAT_SHADOW_ARM_C;
pub const KINTSUGI_FEAT_SARIF: u32 = FEAT_SARIF;
pub const KINTSUGI_FEAT_AUDIT: u32 = FEAT_AUDIT;
pub const KINTSUGI_FEAT_LOGFORGE: u32 = FEAT_LOGFORGE;
pub const KINTSUGI_FEAT_HW_SHA256: u32 = FEAT_HW_SHA256;

#[inline]
const fn compiled_features_mask() -> u32 {
    let mut flags = FEAT_SHA256 | FEAT_SHADOW_ARM_C;
    if cfg!(target_feature = "neon") || cfg!(target_feature = "avx2") {
        flags |= FEAT_SIMD;
    }
    if cfg!(feature = "rule-ir") {
        flags |= FEAT_RULE_IR;
    }
    if cfg!(feature = "sarif") {
        flags |= FEAT_SARIF;
    }
    if cfg!(feature = "audit") {
        flags |= FEAT_AUDIT;
    }
    if cfg!(feature = "logforge") {
        flags |= FEAT_LOGFORGE;
    }
    if cfg!(target_feature = "sha2") || cfg!(target_feature = "sha") {
        flags |= FEAT_HW_SHA256;
    }
    flags
}

#[inline]
fn check_buffer_aliasing(in_ptr: *const u8, in_len: usize, out_ptr: *mut u8, out_cap: usize) -> Result<(), i32> {
    if in_ptr.is_null() || out_ptr.is_null() || in_len == 0 || out_cap == 0 {
        return Ok(());
    }
    let (in_start, out_start) = (in_ptr as usize, out_ptr as usize);
    let in_end = in_start.checked_add(in_len).ok_or(KINTSUGI_FFI_ERR_OVERFLOW)?;
    let out_end = out_start.checked_add(out_cap).ok_or(KINTSUGI_FFI_ERR_OVERFLOW)?;
    if in_start < out_end && out_start < in_end {
        return Err(KINTSUGI_FFI_ERR_INVALID_ARG);
    }
    Ok(())
}

#[inline]
fn check_saturated_overlap(ptr: *const u8, len: usize, target_ptr: *mut u8, target_sz: usize) -> Result<(), i32> {
    if len > (isize::MAX as usize) {
        return Err(KINTSUGI_FFI_ERR_OVERFLOW);
    }
    if ptr.is_null() || target_ptr.is_null() || len == 0 || target_sz == 0 {
        return Ok(());
    }
    let (a_start, b_start) = (ptr as usize, target_ptr as usize);
    let a_end = a_start.checked_add(len).ok_or(KINTSUGI_FFI_ERR_OVERFLOW)?;
    let b_end = b_start.checked_add(target_sz).ok_or(KINTSUGI_FFI_ERR_OVERFLOW)?;
    if a_start < b_end && b_start < a_end {
        return Err(KINTSUGI_FFI_ERR_INVALID_ARG);
    }
    Ok(())
}

/// Validate `output_len` non-null, alignment, and non-overlap against `output` and every input
/// slice (even when lengths exceed DoS caps), then initialize `*output_len = 0`.
///
/// # Safety
/// Caller must ensure `output_len` points to writable memory of at least `size_of::<usize>()`
/// bytes whenever it is non-null, aligned, and disjoint from `output` and `inputs`.
#[inline]
unsafe fn validate_and_zero_output_len(
    output_len: *mut usize,
    output: *mut u8,
    output_capacity: usize,
    inputs: &[(*const u8, usize)],
) -> Result<(), i32> {
    if output_len.is_null() {
        return Err(KINTSUGI_FFI_ERR_NULL_PTR);
    }
    if (output_len as usize) % align_of::<usize>() != 0 {
        return Err(KINTSUGI_FFI_ERR_INVALID_ARG);
    }
    let (len_bytes_ptr, len_sz) = (output_len as *mut u8, size_of::<usize>());
    check_saturated_overlap(output as *const u8, output_capacity, len_bytes_ptr, len_sz)?;
    for &(in_ptr, in_len) in inputs {
        check_saturated_overlap(in_ptr, in_len, len_bytes_ptr, len_sz)?;
    }
    // SAFETY: `output_len` is non-null, naturally aligned to `align_of::<usize>()`, does not wrap
    // address space, and does not overlap `output` or any input slice.
    unsafe { *output_len = 0 };
    Ok(())
}

/// Unified raw-pointer slice validator enforcing `len <= isize::MAX`, non-null (for `len > 0`),
/// and non-wrapping `[ptr, ptr + len)` address arithmetic before constructing `&[u8]`.
///
/// # Safety
/// Caller must ensure that when `len > 0` and `ptr` is non-null, `[ptr, ptr + len)` is allocated,
/// initialized, and immutable for lifetime `'a` (disjoint from any active mutable FFI slice).
#[inline]
pub(crate) unsafe fn checked_slice_range<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if len > (isize::MAX as usize) {
        return Err(KINTSUGI_FFI_ERR_OVERFLOW);
    }
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(KINTSUGI_FFI_ERR_NULL_PTR);
    }
    let _end = (ptr as usize).checked_add(len).ok_or(KINTSUGI_FFI_ERR_OVERFLOW)?;
    // SAFETY: `ptr` is non-null, `u8` has alignment 1, `len <= isize::MAX`, `ptr + len` does not
    // overflow `usize::MAX`, and the FFI caller guarantees `[ptr, ptr + len)` is readable and
    // non-overlapping with mutable output buffers across the call.
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

/// Unified mutable raw-pointer slice validator enforcing `len <= isize::MAX`, non-null (for `len > 0`),
/// and non-wrapping `[ptr, ptr + len)` address arithmetic before constructing `&mut [u8]`.
///
/// # Safety
/// Caller must ensure that when `len > 0` and `ptr` is non-null, `[ptr, ptr + len)` points to
/// valid writable memory exclusively borrowed (non-overlapping with any other pointer) for `'a`.
#[inline]
unsafe fn checked_mut_slice_range<'a>(ptr: *mut u8, len: usize) -> Result<&'a mut [u8], i32> {
    if len > (isize::MAX as usize) {
        return Err(KINTSUGI_FFI_ERR_OVERFLOW);
    }
    if len == 0 {
        return Ok(&mut []);
    }
    if ptr.is_null() {
        return Err(KINTSUGI_FFI_ERR_NULL_PTR);
    }
    let _end = (ptr as usize).checked_add(len).ok_or(KINTSUGI_FFI_ERR_OVERFLOW)?;
    // SAFETY: `ptr` is non-null, `u8` has alignment 1, `len <= isize::MAX`, `ptr + len` does not
    // overflow `usize::MAX`, and caller verified exclusive non-aliasing writability over `[ptr, ptr + len)`.
    Ok(unsafe { slice::from_raw_parts_mut(ptr, len) })
}

#[inline]
unsafe fn utf8_from_raw_checked<'a>(ptr: *const u8, len: usize) -> Result<&'a str, i32> {
    // SAFETY: Caller upholds the `checked_slice_range` readability & non-overlap contract for `(ptr, len)`.
    let raw = unsafe { checked_slice_range(ptr, len) }?;
    std::str::from_utf8(raw).map_err(|_| KINTSUGI_FFI_ERR_INVALID_UTF8)
}

#[inline]
unsafe fn parse_lang_or_default<'a>(ptr: *const u8, len: usize) -> Result<&'a str, i32> {
    // SAFETY: Caller upholds the `utf8_from_raw_checked` readability & non-overlap contract for `(ptr, len)`.
    let trimmed = unsafe { utf8_from_raw_checked(ptr, len) }?.trim();
    Ok(if trimmed.is_empty() { "python" } else { trimmed })
}

/// Upper bound (bytes) for both cached input and cached JSON payload.
const SCAN_CACHE_MAX_BYTES: usize = 262_144;

struct ScanCacheEntry {
    input: Vec<u8>,
    lang: String,
    json: String,
}

thread_local! {
    /// One-shot, single-slot memo for the two-call size-probe pattern (per OS thread).
    static SCAN_JSON_CACHE: RefCell<Option<ScanCacheEntry>> = RefCell::new(None);
}

fn scan_buffer_json_uncached(text: &str, lang: &str) -> String {
    let (mut findings, truncated) =
        crate::scanner::scan_text_buffer_bounded(text, lang, Severity::Low, MAX_REPO_FINDINGS);
    crate::output::deduplicate_findings(&mut findings);
    let arr = render_findings_json_array(&findings);
    JsonObj::with_capacity(224 + arr.len())
        .bool("ok", findings.is_empty())
        .str("schema_version", ENGINE_VERSION)
        .str("engine", "kintsugi-core-ffi")
        .str("version", ENGINE_VERSION)
        .usize("rules_checked", BUILTIN_RULES.len())
        .usize("findings_count", findings.len())
        .bool("truncated", truncated)
        .raw("findings", &arr)
        .finish()
}

/// Return the scan JSON for `(text, lang)`, reusing the previous call's payload on the same thread
/// when input bytes and effective `lang` match exactly (byte compare, no hash collisions). A hit
/// consumes the slot, so the probe → fill sequence keeps at most one bounded entry alive.
pub(crate) fn scan_buffer_cached_json(text: &str, lang: Option<&str>) -> String {
    let lang = match lang.map(str::trim) {
        Some(l) if !l.is_empty() => l,
        _ => "python",
    };
    let hit = SCAN_JSON_CACHE
        .try_with(|slot| {
            let mut slot = slot.try_borrow_mut().ok()?;
            let matches = slot
                .as_ref()
                .is_some_and(|e| e.lang == lang && e.input.as_slice() == text.as_bytes());
            if matches {
                slot.take().map(|e| e.json)
            } else {
                None
            }
        })
        .ok()
        .flatten();
    if let Some(json) = hit {
        return json;
    }
    let json = scan_buffer_json_uncached(text, lang);
    let _ = SCAN_JSON_CACHE.try_with(|slot| {
        if let Ok(mut slot) = slot.try_borrow_mut() {
            *slot = if text.len() <= SCAN_CACHE_MAX_BYTES && json.len() <= SCAN_CACHE_MAX_BYTES {
                Some(ScanCacheEntry { input: text.as_bytes().to_vec(), lang: lang.to_owned(), json: json.clone() })
            } else {
                None
            };
        }
    });
    json
}

#[inline]
unsafe fn write_output_bytes(bytes: &[u8], output: *mut u8, output_capacity: usize, output_len: *mut usize) -> i32 {
    if output_len.is_null() {
        return KINTSUGI_FFI_ERR_NULL_PTR;
    }
    if output_capacity > (isize::MAX as usize) {
        // SAFETY: `output_len` was validated as non-null, aligned, and non-overlapping by `validate_and_zero_output_len`.
        unsafe { *output_len = 0 };
        return KINTSUGI_FFI_ERR_OVERFLOW;
    }
    if output.is_null() {
        if output_capacity == 0 {
            // SAFETY: `output_len` was validated as non-null, aligned, and non-overlapping; size-probe reports required bytes.
            unsafe { *output_len = bytes.len() };
            return KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL;
        }
        // SAFETY: `output_len` was validated as non-null, aligned, and non-overlapping.
        unsafe { *output_len = 0 };
        return KINTSUGI_FFI_ERR_NULL_PTR;
    }
    // SAFETY: `output_len` was validated non-null, aligned, and disjoint from `output` and all inputs.
    unsafe { *output_len = bytes.len() };
    if bytes.len() > output_capacity {
        return KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL;
    }
    if output_capacity > 0 {
        // SAFETY: `output` is non-null, `output_capacity <= isize::MAX`, non-wrapping, and disjoint from `bytes` and `output_len`.
        let Ok(dst) = (unsafe { checked_mut_slice_range(output, output_capacity) }) else {
            // SAFETY: `output_len` remains valid and non-overlapping on slice range error.
            unsafe { *output_len = 0 };
            return KINTSUGI_FFI_ERR_OVERFLOW;
        };
        if !bytes.is_empty() {
            dst[..bytes.len()].copy_from_slice(bytes);
        }
        if bytes.len() < output_capacity {
            dst[bytes.len()] = 0;
        }
    }
    KINTSUGI_FFI_OK
}

/// Return the verified ABI version (`1`).
#[no_mangle]
pub extern "C" fn kintsugi_abi_version() -> u32 {
    catch_unwind(AssertUnwindSafe(|| KINTSUGI_ABI_VERSION)).unwrap_or(0)
}

/// Return compile-time Cargo module & target feature bitflags (`FEAT_*`) driven strictly by `cfg!`.
#[no_mangle]
pub extern "C" fn kintsugi_abi_compiled_features_v1() -> u32 {
    catch_unwind(AssertUnwindSafe(compiled_features_mask)).unwrap_or(0)
}

/// Runtime detection of hardware SHA-256 instructions via `std::arch` (no string comparison).
#[inline]
fn runtime_hw_sha256() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::is_x86_feature_detected!("sha")
            && std::arch::is_x86_feature_detected!("ssse3")
            && std::arch::is_x86_feature_detected!("sse4.1")
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("sha2")
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

/// Return `compiled_features_mask() | runtime_cpu_mask` adding runtime SIMD/SHA2 detection.
#[no_mangle]
pub extern "C" fn kintsugi_abi_features_v1() -> u32 {
    catch_unwind(AssertUnwindSafe(|| {
        use crate::kernels::rule_prefilter::{cached_prefilter_backend, PrefilterBackend};
        let mut flags = compiled_features_mask();
        if cached_prefilter_backend() != PrefilterBackend::RustScalar {
            flags |= FEAT_SIMD;
        }
        if runtime_hw_sha256() {
            flags |= FEAT_HW_SHA256;
        }
        flags
    }))
    .unwrap_or(0)
}

/// Compute FIPS 180-4 SHA-256 into `out_hex[..64]` (plus trailing NUL when `out_cap >= 65`).
///
/// # Safety
/// - `input` must be null only when `input_len == 0`; otherwise it must be valid for reads of
///   `input_len` bytes for the whole call (`input_len <= KINTSUGI_MAX_FFI_INPUT_BYTES`).
/// - `out_hex` must be non-null and valid for writes of `out_cap` bytes (`out_cap <= isize::MAX`).
/// - `[input, input+input_len)` and `[out_hex, out_hex+out_cap)` must not overlap (overlap is
///   detected and rejected with `KINTSUGI_FFI_ERR_INVALID_ARG`); touching ranges are allowed.
/// - No other thread may mutate either buffer during the call.
#[no_mangle]
pub unsafe extern "C" fn kintsugi_sha256_v1(input: *const u8, input_len: usize, out_hex: *mut u8, out_cap: usize) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if out_hex.is_null() {
            return KINTSUGI_FFI_ERR_NULL_PTR;
        }
        if out_cap > (isize::MAX as usize) || input_len > KINTSUGI_MAX_FFI_INPUT_BYTES {
            return KINTSUGI_FFI_ERR_OVERFLOW;
        }
        if let Err(code) = check_buffer_aliasing(input, input_len, out_hex, out_cap) {
            return code;
        }
        // SAFETY: `input` and `out_hex` are verified disjoint; `input_len <= KINTSUGI_MAX_FFI_INPUT_BYTES`.
        let data = match unsafe { checked_slice_range(input, input_len) } {
            Ok(s) => s,
            Err(code) => return code,
        };
        if out_cap < 64 {
            return KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL;
        }
        // SAFETY: `out_hex` is non-null, `64 <= out_cap <= isize::MAX`, and verified non-overlapping with `input`.
        let dst = match unsafe { checked_mut_slice_range(out_hex, out_cap) } {
            Ok(s) => s,
            Err(code) => return code,
        };
        let mut hex_buf = [0u8; 64];
        sha256_hex_into(data, &mut hex_buf, false);
        dst[..64].copy_from_slice(&hex_buf);
        if out_cap >= 65 {
            dst[64] = 0;
        }
        KINTSUGI_FFI_OK
    }))
    .unwrap_or(KINTSUGI_FFI_ERR_PANIC)
}

/// Scan an in-memory UTF-8 source buffer with bounded allocation (`<= MAX_REPO_FINDINGS`).
///
/// # Safety
/// - `output_len` must be non-null, aligned for `usize`, valid for writes, and must not overlap
///   any input buffer or `output`.
/// - `input` (`input_len <= 16 MiB`) and `lang_ptr` (`lang_len <= 64 B`) must be null only when
///   their length is 0; otherwise valid for reads of that length for the whole call.
/// - `output` must be valid for writes of `output_capacity` bytes, or null with capacity 0
///   (a size probe: returns `KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL` and the required length).
/// - `output` must not overlap any input; inputs may alias each other (read-only).
/// - No other thread may mutate these buffers during the call.
#[no_mangle]
pub unsafe extern "C" fn kintsugi_scan_buffer_v1(
    input: *const u8, input_len: usize, lang_ptr: *const u8, lang_len: usize,
    output: *mut u8, output_capacity: usize, output_len: *mut usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let ins = [(input, input_len), (lang_ptr, lang_len)];
        // SAFETY: Validates `output_len` non-null, alignment, and disjointness before writing `*output_len = 0`.
        if let Err(c) = unsafe { validate_and_zero_output_len(output_len, output, output_capacity, &ins) } { return c; }
        if output_capacity > (isize::MAX as usize) || input_len > KINTSUGI_MAX_FFI_INPUT_BYTES || lang_len > KINTSUGI_MAX_FFI_LANG_BYTES {
            return KINTSUGI_FFI_ERR_OVERFLOW;
        }
        if output.is_null() && output_capacity > 0 { return KINTSUGI_FFI_ERR_NULL_PTR; }
        for (p, l) in ins {
            if let Err(c) = check_buffer_aliasing(p, l, output, output_capacity) { return c; }
        }
        // SAFETY: `input` is bounded (`<= 16 MiB`) and verified disjoint from mutable `output` and `output_len`.
        let code_str = match unsafe { utf8_from_raw_checked(input, input_len) } { Ok(s) => s, Err(c) => return c };
        // SAFETY: `lang_ptr` is bounded (`<= 64 B`) and verified disjoint from mutable `output` and `output_len`.
        let lang_str = match unsafe { parse_lang_or_default(lang_ptr, lang_len) } { Ok(s) => s, Err(c) => return c };

        let payload = scan_buffer_cached_json(code_str, Some(lang_str));
        // SAFETY: `payload` is freshly heap-allocated locally; `output` and `output_len` were validated non-aliasing.
        unsafe { write_output_bytes(payload.as_bytes(), output, output_capacity, output_len) }
    }))
    .unwrap_or(KINTSUGI_FFI_ERR_PANIC)
}

/// Evaluate a canonical `RuleIR/1` JSON rule against an in-memory UTF-8 buffer (zero FS/network IO).
///
/// Returns `KINTSUGI_FFI_ERR_INTERNAL` when built without the `rule-ir` feature.
///
/// # Safety
/// - `output_len` must be non-null, aligned for `usize`, valid for writes, and must not overlap
///   any input buffer or `output`.
/// - `rule_json_ptr` (`<= 1 MiB`), `code_ptr` (`<= 16 MiB`) and `lang_ptr` (`<= 64 B`) must be
///   null only when their length is 0; otherwise valid for reads of that length for the whole call.
/// - `output` must be valid for writes of `output_capacity` bytes, or null with capacity 0 (size probe).
/// - `output` must not overlap any input; inputs may alias each other (read-only).
/// - No other thread may mutate these buffers during the call.
#[no_mangle]
pub unsafe extern "C" fn kintsugi_rule_ir_eval_v1(
    rule_json_ptr: *const u8, rule_json_len: usize, code_ptr: *const u8, code_len: usize,
    lang_ptr: *const u8, lang_len: usize, output: *mut u8, output_capacity: usize, output_len: *mut usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let ins = [(rule_json_ptr, rule_json_len), (code_ptr, code_len), (lang_ptr, lang_len)];
        // SAFETY: Validates `output_len` non-null, alignment, and disjointness before writing `*output_len = 0`.
        if let Err(c) = unsafe { validate_and_zero_output_len(output_len, output, output_capacity, &ins) } { return c; }
        if output_capacity > (isize::MAX as usize) || rule_json_len > KINTSUGI_MAX_FFI_RULE_BYTES
            || code_len > KINTSUGI_MAX_FFI_INPUT_BYTES || lang_len > KINTSUGI_MAX_FFI_LANG_BYTES
        {
            return KINTSUGI_FFI_ERR_OVERFLOW;
        }
        if output.is_null() && output_capacity > 0 { return KINTSUGI_FFI_ERR_NULL_PTR; }
        for (p, l) in ins {
            if let Err(c) = check_buffer_aliasing(p, l, output, output_capacity) { return c; }
        }
        // SAFETY: `rule_json_ptr` is bounded (`<= 1 MiB`) and verified disjoint from mutable `output` and `output_len`.
        let rule_str = match unsafe { utf8_from_raw_checked(rule_json_ptr, rule_json_len) } { Ok(s) => s, Err(c) => return c };
        // SAFETY: `code_ptr` is bounded (`<= 16 MiB`) and verified disjoint from mutable `output` and `output_len`.
        let code_str = match unsafe { utf8_from_raw_checked(code_ptr, code_len) } { Ok(s) => s, Err(c) => return c };
        // SAFETY: `lang_ptr` is bounded (`<= 64 B`) and verified disjoint from mutable `output` and `output_len`.
        let lang_str = match unsafe { parse_lang_or_default(lang_ptr, lang_len) } { Ok(s) => s, Err(c) => return c };

        #[cfg(feature = "rule-ir")]
        {
            let Ok(result_json) = crate::rule_ir::evaluate_rule_ir_json_no_fs(rule_str, code_str, lang_str) else {
                return KINTSUGI_FFI_ERR_RULE_INVALID;
            };
            // SAFETY: `result_json` is freshly heap-allocated locally; `output` and `output_len` were validated non-aliasing.
            unsafe { write_output_bytes(result_json.as_bytes(), output, output_capacity, output_len) }
        }
        #[cfg(not(feature = "rule-ir"))]
        {
            let _ = (rule_str, code_str, lang_str, output, output_capacity);
            KINTSUGI_FFI_ERR_INTERNAL
        }
    }))
    .unwrap_or(KINTSUGI_FFI_ERR_PANIC)
}

/// Alias entrypoint for `kintsugi_rule_ir_eval_v1`.
///
/// ALWAYS exported in every feature configuration. Without the `rule-ir` feature it still
/// validates its arguments, zeroes `*output_len`, and returns `KINTSUGI_FFI_ERR_INTERNAL`.
///
/// # Safety
/// Same contract as [`kintsugi_rule_ir_eval_v1`].
#[no_mangle]
pub unsafe extern "C" fn kintsugi_eval_rule_ir_v1(
    rule_json_ptr: *const u8, rule_json_len: usize, code_ptr: *const u8, code_len: usize,
    lang_ptr: *const u8, lang_len: usize, output: *mut u8, output_capacity: usize, output_len: *mut usize,
) -> i32 {
    // SAFETY: Caller upholds the identical `# Safety` contract, forwarded verbatim.
    unsafe {
        kintsugi_rule_ir_eval_v1(rule_json_ptr, rule_json_len, code_ptr, code_len, lang_ptr, lang_len, output, output_capacity, output_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn abi_version_compiled_vs_runtime_features_and_sha256() {
        // SAFETY: All pointers are null (rejected before deref) or point to live local buffers of the stated length.
        unsafe {
        assert_eq!(kintsugi_abi_version(), 1);
        let (compiled, runtime) = (kintsugi_abi_compiled_features_v1(), kintsugi_abi_features_v1());
        assert_eq!(runtime & compiled, compiled);
        assert_eq!(compiled & (FEAT_SHA256 | FEAT_SHADOW_ARM_C), FEAT_SHA256 | FEAT_SHADOW_ARM_C);
        assert_eq!((compiled & FEAT_RULE_IR) != 0, cfg!(feature = "rule-ir"));
        assert_eq!((compiled & FEAT_SARIF) != 0, cfg!(feature = "sarif"));
        assert_eq!((compiled & FEAT_AUDIT) != 0, cfg!(feature = "audit"));
        assert_eq!((compiled & FEAT_LOGFORGE) != 0, cfg!(feature = "logforge"));

        let mut out = [0u8; 65];
        assert_eq!(kintsugi_sha256_v1(ptr::null(), 5, out.as_mut_ptr(), out.len()), KINTSUGI_FFI_ERR_NULL_PTR);
        assert_eq!(kintsugi_sha256_v1(b"abc".as_ptr(), 3, ptr::null_mut(), 65), KINTSUGI_FFI_ERR_NULL_PTR);
        assert_eq!(kintsugi_sha256_v1(b"abc".as_ptr(), 3, out.as_mut_ptr(), 63), KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL);
        assert_eq!(kintsugi_sha256_v1(b"abc".as_ptr(), usize::MAX, out.as_mut_ptr(), 65), KINTSUGI_FFI_ERR_OVERFLOW);
        assert_eq!(kintsugi_sha256_v1(b"abc".as_ptr(), 3, out.as_mut_ptr(), 65), KINTSUGI_FFI_OK);
        assert_eq!(&out[..64], b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(out[64], 0);
        assert_eq!(kintsugi_sha256_v1(ptr::null(), 0, out.as_mut_ptr(), 64), KINTSUGI_FFI_OK);
        }
    }

    #[test]
    fn scan_buffer_truncation_cap_aliasing_and_error_output_len_zeroed() {
        let (code, lang) = (b"import yaml\ncfg = yaml.load(raw, Loader=yaml.Loader)\n", b"python");
        let (mut small, mut out_len) = ([0u8; 8], 0usize);
        // SAFETY: Inputs/outputs are live, disjoint local buffers with matching lengths, or null with capacity 0/rejected.
        unsafe {
        assert_eq!(
            kintsugi_scan_buffer_v1(code.as_ptr(), code.len(), lang.as_ptr(), lang.len(), small.as_mut_ptr(), small.len(), &mut out_len),
            KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL
        );
        assert!(out_len > 8);
        let mut full = vec![0u8; out_len + 1];
        assert_eq!(
            kintsugi_scan_buffer_v1(code.as_ptr(), code.len(), lang.as_ptr(), lang.len(), full.as_mut_ptr(), full.len(), &mut out_len),
            KINTSUGI_FFI_OK
        );
        let json_str = std::str::from_utf8(&full[..out_len]).unwrap();
        assert!(json_str.contains("KS-020") && json_str.contains("\"truncated\":false") && json_str.contains("\"schema_version\":\"3.0.0\""));

        let bad_utf8 = [0xFFu8, 0xFEu8];
        out_len = 777;
        assert_eq!(
            kintsugi_scan_buffer_v1(bad_utf8.as_ptr(), bad_utf8.len(), lang.as_ptr(), lang.len(), full.as_mut_ptr(), full.len(), &mut out_len),
            KINTSUGI_FFI_ERR_INVALID_UTF8
        );
        assert_eq!(out_len, 0);

        out_len = 888;
        assert_eq!(
            kintsugi_scan_buffer_v1(code.as_ptr(), code.len(), lang.as_ptr(), lang.len(), ptr::null_mut(), 16, &mut out_len),
            KINTSUGI_FFI_ERR_NULL_PTR
        );
        assert_eq!(out_len, 0);

        let flood = "import os\n".to_string() + &"os.system(cmd)\n".repeat(MAX_REPO_FINDINGS + 12);
        let mut needed = 0usize;
        assert_eq!(kintsugi_scan_buffer_v1(flood.as_ptr(), flood.len(), lang.as_ptr(), lang.len(), ptr::null_mut(), 0, &mut needed), KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL);
        let mut flood_out = vec![0u8; needed];
        assert_eq!(kintsugi_scan_buffer_v1(flood.as_ptr(), flood.len(), lang.as_ptr(), lang.len(), flood_out.as_mut_ptr(), flood_out.len(), &mut needed), KINTSUGI_FFI_OK);
        let flood_json = std::str::from_utf8(&flood_out[..needed]).unwrap();
        assert!(flood_json.contains("\"findings_count\":10000") && flood_json.contains("\"truncated\":true"));
        }
    }

    #[test]
    fn dos_caps_zero_size_probe_and_rule_ir_feature_gate() {
        let (code, lang) = (b"x = 1\n", b"python");
        let (mut needed, mut written) = (0usize, 0usize);
        // SAFETY: Oversized lengths are rejected by the DoS caps before any deref; other pointers are live local buffers.
        unsafe {
        assert_eq!(kintsugi_scan_buffer_v1(code.as_ptr(), code.len(), lang.as_ptr(), lang.len(), ptr::null_mut(), 0, &mut needed), KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL);
        let mut needed_again = 0usize;
        assert_eq!(kintsugi_scan_buffer_v1(code.as_ptr(), code.len(), lang.as_ptr(), lang.len(), ptr::null_mut(), 0, &mut needed_again), KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL);
        assert!(needed > 0 && needed_again == needed, "two consecutive size probes must be deterministic");
        let mut exact_buf = vec![0u8; needed];
        assert_eq!(kintsugi_scan_buffer_v1(code.as_ptr(), code.len(), lang.as_ptr(), lang.len(), exact_buf.as_mut_ptr(), exact_buf.len(), &mut written), KINTSUGI_FFI_OK);
        assert_eq!(written, needed);
        assert_eq!(kintsugi_scan_buffer_v1(code.as_ptr(), KINTSUGI_MAX_FFI_INPUT_BYTES + 1, lang.as_ptr(), lang.len(), exact_buf.as_mut_ptr(), exact_buf.len(), &mut written), KINTSUGI_FFI_ERR_OVERFLOW);
        assert_eq!(written, 0);
        written = 42;
        assert_eq!(kintsugi_scan_buffer_v1(code.as_ptr(), code.len(), lang.as_ptr(), KINTSUGI_MAX_FFI_LANG_BYTES + 1, exact_buf.as_mut_ptr(), exact_buf.len(), &mut written), KINTSUGI_FFI_ERR_OVERFLOW);
        assert_eq!(written, 0);
        written = 42;
        assert_eq!(kintsugi_rule_ir_eval_v1(b"{}".as_ptr(), KINTSUGI_MAX_FFI_RULE_BYTES + 1, code.as_ptr(), code.len(), lang.as_ptr(), lang.len(), exact_buf.as_mut_ptr(), exact_buf.len(), &mut written), KINTSUGI_FFI_ERR_OVERFLOW);
        assert_eq!(written, 0);

        written = 99;
        let expected_ir_err = if cfg!(feature = "rule-ir") { KINTSUGI_FFI_ERR_RULE_INVALID } else { KINTSUGI_FFI_ERR_INTERNAL };
        assert_eq!(kintsugi_eval_rule_ir_v1(b"{}".as_ptr(), 2, code.as_ptr(), code.len(), lang.as_ptr(), lang.len(), exact_buf.as_mut_ptr(), exact_buf.len(), &mut written), expected_ir_err);
        assert_eq!(written, 0);
        }
    }

    #[test]
    fn pairwise_aliasing_permutations_and_checked_slice_range_invariants() {
        // SAFETY: Exercising rejected null/overflow/wraparound branches before any dereference.
        unsafe {
            assert_eq!(checked_slice_range(ptr::null(), 0).unwrap(), b"");
            assert_eq!(checked_slice_range(ptr::null(), 1).unwrap_err(), KINTSUGI_FFI_ERR_NULL_PTR);
            assert_eq!(checked_slice_range(b"x".as_ptr(), (isize::MAX as usize) + 1).unwrap_err(), KINTSUGI_FFI_ERR_OVERFLOW);
            assert_eq!(checked_slice_range((usize::MAX - 3) as *const u8, 8).unwrap_err(), KINTSUGI_FFI_ERR_OVERFLOW);
        }

        let mut arena = [b'a'; 512];
        arena[..6].copy_from_slice(b"python");
        let arena_base = arena.as_mut_ptr();
        let arena_const = arena_base as *const u8;
        let (mut sep_out, mut out_len) = ([0u8; 512], 123usize);
        let mut word = 0usize;
        let word_ptr: *mut usize = &mut word;
        let word_bytes = word_ptr as *mut u8;
        let wsz = size_of::<usize>();
        let arena_off = |off: usize| -> *mut u8 {
            // SAFETY: `off <= 64 < arena.len()` stays strictly within the 512-byte stack `arena`.
            unsafe { arena_base.add(off) }
        };

        // SAFETY: Overlapping ranges all lie inside live stack `arena`; aliasing is rejected before any write.
        unsafe {
        // 1. Mutable `output` aliasing against `input`, `lang`, `rule`, `code`, and `output_len`
        assert_eq!(kintsugi_sha256_v1(arena_const, 32, arena_off(16), 65), KINTSUGI_FFI_ERR_INVALID_ARG);
        assert_eq!(kintsugi_scan_buffer_v1(arena_const, 32, b"python".as_ptr(), 6, arena_off(8), 64, &mut out_len), KINTSUGI_FFI_ERR_INVALID_ARG);
        assert_eq!(out_len, 0);
        out_len = 55;
        assert_eq!(kintsugi_scan_buffer_v1(b"x=1\n".as_ptr(), 4, arena_const, 6, arena_off(2), 64, &mut out_len), KINTSUGI_FFI_ERR_INVALID_ARG);
        assert_eq!(out_len, 0);
        out_len = 55;
        assert_eq!(kintsugi_rule_ir_eval_v1(arena_const, 16, b"x=1\n".as_ptr(), 4, b"python".as_ptr(), 6, arena_off(4), 64, &mut out_len), KINTSUGI_FFI_ERR_INVALID_ARG);
        assert_eq!(out_len, 0);
        out_len = 55;
        assert_eq!(kintsugi_rule_ir_eval_v1(b"{}".as_ptr(), 2, arena_const, 16, b"python".as_ptr(), 6, arena_off(8), 64, &mut out_len), KINTSUGI_FFI_ERR_INVALID_ARG);
        assert_eq!(out_len, 0);
        out_len = 55;
        assert_eq!(kintsugi_rule_ir_eval_v1(b"{}".as_ptr(), 2, b"x=1\n".as_ptr(), 4, arena_const, 6, arena_off(1), 64, &mut out_len), KINTSUGI_FFI_ERR_INVALID_ARG);
        assert_eq!(out_len, 0);
        }

        // SAFETY: `word`, `sep_out`, `arena` are live locals; aliasing/misalignment is rejected before any deref.
        unsafe {
        // 2. Mutable `output_len` aliasing against `output`, `input`, `lang`, `rule`, and `code` + unaligned `output_len`
        assert_eq!(kintsugi_scan_buffer_v1(b"x=1\n".as_ptr(), 4, b"python".as_ptr(), 6, word_bytes, wsz, word_ptr), KINTSUGI_FFI_ERR_INVALID_ARG);
        assert_eq!(kintsugi_scan_buffer_v1(word_bytes as *const u8, wsz, b"python".as_ptr(), 6, sep_out.as_mut_ptr(), sep_out.len(), word_ptr), KINTSUGI_FFI_ERR_INVALID_ARG);
        assert_eq!(kintsugi_scan_buffer_v1(b"x=1\n".as_ptr(), 4, word_bytes as *const u8, wsz, sep_out.as_mut_ptr(), sep_out.len(), word_ptr), KINTSUGI_FFI_ERR_INVALID_ARG);
        assert_eq!(kintsugi_rule_ir_eval_v1(word_bytes as *const u8, wsz, b"x=1\n".as_ptr(), 4, b"python".as_ptr(), 6, sep_out.as_mut_ptr(), sep_out.len(), word_ptr), KINTSUGI_FFI_ERR_INVALID_ARG);
        assert_eq!(kintsugi_rule_ir_eval_v1(b"{}".as_ptr(), 2, word_bytes as *const u8, wsz, b"python".as_ptr(), 6, sep_out.as_mut_ptr(), sep_out.len(), word_ptr), KINTSUGI_FFI_ERR_INVALID_ARG);
        assert_eq!(kintsugi_rule_ir_eval_v1(b"{}".as_ptr(), 2, b"x=1\n".as_ptr(), 4, word_bytes as *const u8, wsz, sep_out.as_mut_ptr(), sep_out.len(), word_ptr), KINTSUGI_FFI_ERR_INVALID_ARG);
        // Intentional 1-byte offset inside `sep_out` (safe `wrapping_add`) to test misaligned `usize` rejection.
        let unaligned_out_len = sep_out.as_mut_ptr().wrapping_add(1) as *mut usize;
        assert_eq!(kintsugi_scan_buffer_v1(b"x=1\n".as_ptr(), 4, b"python".as_ptr(), 6, arena_base, 64, unaligned_out_len), KINTSUGI_FFI_ERR_INVALID_ARG);
        }

        // SAFETY: Read-only inputs may alias; `arena[0..16]` and `arena[16..81]` only touch, never overlap.
        unsafe {
        // 3. Shared immutable inputs (`input == lang`) and adjacent touching slices (`in_end == out_start`) are valid & non-UB
        assert_eq!(kintsugi_scan_buffer_v1(arena_const, 6, arena_const, 6, sep_out.as_mut_ptr(), sep_out.len(), &mut out_len), KINTSUGI_FFI_OK);
        assert_eq!(kintsugi_sha256_v1(arena_const, 16, arena_off(16), 65), KINTSUGI_FFI_OK);
        }
        let _ = (&arena, &word);
    }
}
