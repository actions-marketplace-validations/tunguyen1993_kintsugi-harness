//! Verified C-ABI FFI Surface (`kintsugi_core::ffi`, ABI v1).
//!
//! Safety guarantees:
//! - Every `extern "C"` entrypoint is wrapped in `std::panic::catch_unwind(AssertUnwindSafe(...))`
//!   so Rust panics never unwind across the C ABI boundary.
//! - All raw pointers, lengths, and output capacities are validated against NULL, `isize::MAX`
//!   overflow, invalid UTF-8, and insufficient capacity with explicit negative error codes.
//! - Zero filesystem access, zero network access, and zero global mutable state.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

use crate::kernels::sha256_hw::sha256_hex_into;
use crate::{evaluate_rule_ir_json_no_fs, json_escape, scan_text_buffer_no_fs, Severity, BUILTIN_RULES};

pub const KINTSUGI_ABI_VERSION: u32 = 1;

pub const KINTSUGI_FFI_OK: i32 = 0;
pub const KINTSUGI_FFI_ERR_NULL_PTR: i32 = -1;
pub const KINTSUGI_FFI_ERR_INVALID_UTF8: i32 = -2;
pub const KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL: i32 = -3;
pub const KINTSUGI_FFI_ERR_INVALID_ARG: i32 = -4;
pub const KINTSUGI_FFI_ERR_RULE_INVALID: i32 = -5;
pub const KINTSUGI_FFI_ERR_OVERFLOW: i32 = -6;
pub const KINTSUGI_FFI_ERR_PANIC: i32 = -99;

#[inline]
unsafe fn slice_from_raw_checked<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if len > (isize::MAX as usize) {
        return Err(KINTSUGI_FFI_ERR_OVERFLOW);
    }
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(KINTSUGI_FFI_ERR_NULL_PTR);
    }
    // SAFETY: Caller guarantees `[ptr, ptr + len)` is valid for reads; `len <= isize::MAX`
    // and non-null were checked immediately above.
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

#[inline]
unsafe fn write_output_bytes(
    bytes: &[u8],
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {
    if output_len.is_null() {
        return KINTSUGI_FFI_ERR_NULL_PTR;
    }
    if output_capacity > (isize::MAX as usize) {
        return KINTSUGI_FFI_ERR_OVERFLOW;
    }
    if output.is_null() {
        // SAFETY: `output_len` was checked non-null above.
        unsafe { *output_len = bytes.len() };
        return KINTSUGI_FFI_ERR_NULL_PTR;
    }
    // SAFETY: `output_len` is valid and aligned per caller contract.
    unsafe { *output_len = bytes.len() };
    if bytes.len() > output_capacity {
        return KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL;
    }
    // SAFETY: `output` is non-null and has at least `output_capacity >= bytes.len()` writable bytes.
    let dst = unsafe { slice::from_raw_parts_mut(output, output_capacity) };
    if !bytes.is_empty() {
        dst[..bytes.len()].copy_from_slice(bytes);
    }
    if bytes.len() < output_capacity {
        dst[bytes.len()] = 0;
    }
    KINTSUGI_FFI_OK
}

/// Return the verified ABI version (`1`).
#[no_mangle]
pub extern "C" fn kintsugi_abi_version() -> u32 {
    catch_unwind(AssertUnwindSafe(|| KINTSUGI_ABI_VERSION)).unwrap_or(0)
}

/// Compute FIPS 180-4 SHA-256 (hardware `FEAT_SHA256` when available) into `out_hex[..64]`.
///
/// Writes 64 lowercase ASCII hex bytes (plus trailing NUL if `out_cap >= 65`).
#[no_mangle]
pub extern "C" fn kintsugi_sha256_v1(
    input: *const u8,
    input_len: usize,
    out_hex: *mut u8,
    out_cap: usize,
) -> i32 {
    let res = catch_unwind(AssertUnwindSafe(|| {
        if out_hex.is_null() {
            return KINTSUGI_FFI_ERR_NULL_PTR;
        }
        if out_cap > (isize::MAX as usize) {
            return KINTSUGI_FFI_ERR_OVERFLOW;
        }
        // SAFETY: pointer/len validation performed inside `slice_from_raw_checked`.
        let data = match unsafe { slice_from_raw_checked(input, input_len) } {
            Ok(s) => s,
            Err(code) => return code,
        };
        if out_cap < 64 {
            return KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL;
        }
        let mut hex_buf = [0u8; 64];
        sha256_hex_into(data, &mut hex_buf, false);
        // SAFETY: `out_hex` is non-null and `out_cap >= 64`.
        let dst = unsafe { slice::from_raw_parts_mut(out_hex, out_cap) };
        dst[..64].copy_from_slice(&hex_buf);
        if out_cap >= 65 {
            dst[64] = 0;
        }
        KINTSUGI_FFI_OK
    }));
    res.unwrap_or(KINTSUGI_FFI_ERR_PANIC)
}

/// Scan an in-memory UTF-8 source buffer against all 36 built-in rules (zero filesystem/network IO).
///
/// Writes JSON scan payload to `output` and byte count to `*output_len`.
/// Returns `KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL` (`-3`) with required size in `*output_len` if `output_capacity` is too small.
#[no_mangle]
pub extern "C" fn kintsugi_scan_buffer_v1(
    input: *const u8,
    input_len: usize,
    lang_ptr: *const u8,
    lang_len: usize,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {
    let res = catch_unwind(AssertUnwindSafe(|| {
        if output_len.is_null() {
            return KINTSUGI_FFI_ERR_NULL_PTR;
        }
        if output_capacity > (isize::MAX as usize) {
            return KINTSUGI_FFI_ERR_OVERFLOW;
        }
        // SAFETY: validated via `slice_from_raw_checked`.
        let input_bytes = match unsafe { slice_from_raw_checked(input, input_len) } {
            Ok(s) => s,
            Err(code) => return code,
        };
        let lang_bytes = match unsafe { slice_from_raw_checked(lang_ptr, lang_len) } {
            Ok(s) => s,
            Err(code) => return code,
        };
        let code_str = match std::str::from_utf8(input_bytes) {
            Ok(s) => s,
            Err(_) => return KINTSUGI_FFI_ERR_INVALID_UTF8,
        };
        let lang_str = match std::str::from_utf8(lang_bytes) {
            Ok(s) => {
                let t = s.trim();
                if t.is_empty() {
                    "python"
                } else {
                    t
                }
            }
            Err(_) => return KINTSUGI_FFI_ERR_INVALID_UTF8,
        };

        let findings = scan_text_buffer_no_fs(code_str, "<ffi:buffer>", lang_str, Severity::Low);
        let items: Vec<String> = findings
            .iter()
            .map(|f| {
                format!(
                    "{{\"scar_id\":\"{}\",\"severity\":\"{}\",\"category\":\"{}\",\"file_path\":\"{}\",\"line\":{},\"column\":{},\"title\":\"{}\",\"snippet\":\"{}\",\"good_code_hint\":\"{}\"}}",
                    json_escape(&f.scar_id),
                    f.severity.as_str(),
                    json_escape(&f.category),
                    json_escape(&f.file_path),
                    f.line,
                    f.column,
                    json_escape(&f.title),
                    json_escape(&f.snippet),
                    json_escape(&f.fix_hint)
                )
            })
            .collect();
        let payload = format!(
            "{{\"ok\":true,\"schema_version\":\"2.4.0\",\"engine\":\"kintsugi_core_ffi\",\"abi_version\":{},\"active_scars\":{},\"findings_count\":{},\"findings\":[{}]}}",
            KINTSUGI_ABI_VERSION,
            BUILTIN_RULES.len(),
            findings.len(),
            items.join(",")
        );

        // SAFETY: `output`, `output_capacity`, and `output_len` are validated in `write_output_bytes`.
        unsafe { write_output_bytes(payload.as_bytes(), output, output_capacity, output_len) }
    }));
    res.unwrap_or(KINTSUGI_FFI_ERR_PANIC)
}

/// Evaluate a canonical `RuleIR/1` JSON rule against an in-memory UTF-8 buffer (zero filesystem/network IO).
#[no_mangle]
pub extern "C" fn kintsugi_rule_ir_eval_v1(
    rule_json_ptr: *const u8,
    rule_json_len: usize,
    code_ptr: *const u8,
    code_len: usize,
    lang_ptr: *const u8,
    lang_len: usize,
    output: *mut u8,
    output_capacity: usize,
    output_len: *mut usize,
) -> i32 {
    let res = catch_unwind(AssertUnwindSafe(|| {
        if output_len.is_null() {
            return KINTSUGI_FFI_ERR_NULL_PTR;
        }
        if output_capacity > (isize::MAX as usize) {
            return KINTSUGI_FFI_ERR_OVERFLOW;
        }
        // SAFETY: validated via `slice_from_raw_checked`.
        let rule_bytes = match unsafe { slice_from_raw_checked(rule_json_ptr, rule_json_len) } {
            Ok(s) => s,
            Err(code) => return code,
        };
        let code_bytes = match unsafe { slice_from_raw_checked(code_ptr, code_len) } {
            Ok(s) => s,
            Err(code) => return code,
        };
        let lang_bytes = match unsafe { slice_from_raw_checked(lang_ptr, lang_len) } {
            Ok(s) => s,
            Err(code) => return code,
        };
        let rule_str = match std::str::from_utf8(rule_bytes) {
            Ok(s) => s,
            Err(_) => return KINTSUGI_FFI_ERR_INVALID_UTF8,
        };
        let code_str = match std::str::from_utf8(code_bytes) {
            Ok(s) => s,
            Err(_) => return KINTSUGI_FFI_ERR_INVALID_UTF8,
        };
        let lang_str = match std::str::from_utf8(lang_bytes) {
            Ok(s) => {
                let t = s.trim();
                if t.is_empty() {
                    "python"
                } else {
                    t
                }
            }
            Err(_) => return KINTSUGI_FFI_ERR_INVALID_UTF8,
        };

        let result_json = match evaluate_rule_ir_json_no_fs(rule_str, code_str, lang_str) {
            Ok(j) => j,
            Err(_) => return KINTSUGI_FFI_ERR_RULE_INVALID,
        };
        // SAFETY: validated inside `write_output_bytes`.
        unsafe { write_output_bytes(result_json.as_bytes(), output, output_capacity, output_len) }
    }));
    res.unwrap_or(KINTSUGI_FFI_ERR_PANIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn abi_version_and_sha256_bounds_checks() {
        assert_eq!(kintsugi_abi_version(), 1);
        let mut out = [0u8; 65];
        assert_eq!(
            kintsugi_sha256_v1(ptr::null(), 5, out.as_mut_ptr(), out.len()),
            KINTSUGI_FFI_ERR_NULL_PTR
        );
        assert_eq!(
            kintsugi_sha256_v1(b"abc".as_ptr(), 3, ptr::null_mut(), 65),
            KINTSUGI_FFI_ERR_NULL_PTR
        );
        assert_eq!(
            kintsugi_sha256_v1(b"abc".as_ptr(), 3, out.as_mut_ptr(), 63),
            KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL
        );
        assert_eq!(
            kintsugi_sha256_v1(b"abc".as_ptr(), usize::MAX, out.as_mut_ptr(), 65),
            KINTSUGI_FFI_ERR_OVERFLOW
        );
        assert_eq!(
            kintsugi_sha256_v1(b"abc".as_ptr(), 3, out.as_mut_ptr(), 65),
            KINTSUGI_FFI_OK
        );
        assert_eq!(
            &out[..64],
            b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(out[64], 0);
        // Empty buffer with NULL pointer and len=0 works cleanly
        assert_eq!(
            kintsugi_sha256_v1(ptr::null(), 0, out.as_mut_ptr(), 64),
            KINTSUGI_FFI_OK
        );
        assert_eq!(
            &out[..64],
            b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn scan_buffer_handles_small_buffer_invalid_utf8_and_findings() {
        let code = b"import yaml\ncfg = yaml.load(raw, Loader=yaml.Loader)\n";
        let lang = b"python";
        let mut small = [0u8; 8];
        let mut out_len = 0usize;
        let rc = kintsugi_scan_buffer_v1(
            code.as_ptr(),
            code.len(),
            lang.as_ptr(),
            lang.len(),
            small.as_mut_ptr(),
            small.len(),
            &mut out_len,
        );
        assert_eq!(rc, KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL);
        assert!(out_len > small.len());

        let mut full = vec![0u8; out_len + 1];
        let rc2 = kintsugi_scan_buffer_v1(
            code.as_ptr(),
            code.len(),
            lang.as_ptr(),
            lang.len(),
            full.as_mut_ptr(),
            full.len(),
            &mut out_len,
        );
        assert_eq!(rc2, KINTSUGI_FFI_OK);
        let json_str = std::str::from_utf8(&full[..out_len]).unwrap();
        assert!(json_str.contains("KS-020"), "{json_str}");

        let bad_utf8 = [0xFFu8, 0xFEu8];
        assert_eq!(
            kintsugi_scan_buffer_v1(
                bad_utf8.as_ptr(),
                bad_utf8.len(),
                lang.as_ptr(),
                lang.len(),
                full.as_mut_ptr(),
                full.len(),
                &mut out_len,
            ),
            KINTSUGI_FFI_ERR_INVALID_UTF8
        );
        assert_eq!(
            kintsugi_scan_buffer_v1(
                code.as_ptr(),
                code.len(),
                lang.as_ptr(),
                lang.len(),
                ptr::null_mut(),
                16,
                &mut out_len,
            ),
            KINTSUGI_FFI_ERR_NULL_PTR
        );
    }
}
