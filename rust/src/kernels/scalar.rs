//! Tier 2: Safe Scalar Reference Kernels for LogForge (`kintsugi_core::kernels::scalar`).
//!
//! Zero `unsafe` code. Serves both as the readable Rust baseline and the
//! deterministic fallback when SIMD execution is disabled (`disable_simd = true`)
//! or unavailable on the target CPU.

/// Scan `data` for all exact byte offsets where `data[i] == delim`.
#[inline]
pub fn scan_delimiters_scalar(data: &[u8], delim: u8) -> Vec<usize> {
    let mut out = Vec::new();
    scan_delimiters_scalar_into(data, delim, &mut out);
    out
}

/// Append all exact byte offsets where `data[i] == delim` into `out`.
#[inline]
pub fn scan_delimiters_scalar_into(data: &[u8], delim: u8, out: &mut Vec<usize>) {
    for (idx, &byte) in data.iter().enumerate() {
        if byte == delim {
            out.push(idx);
        }
    }
}

/// Count occurrences of `delim` in `data` using safe scalar iteration.
#[inline]
pub fn count_delimiters_scalar(data: &[u8], delim: u8) -> usize {
    let mut count = 0usize;
    for &byte in data {
        if byte == delim {
            count += 1;
        }
    }
    count
}

/// Scan `data` left-to-right for non-overlapping occurrences of multi-byte `pattern`.
///
/// Returns an empty `Vec` if `pattern` is empty or longer than `data`.
#[inline]
pub fn scan_multibyte_delimiters_scalar(data: &[u8], pattern: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    scan_multibyte_delimiters_scalar_into(data, pattern, &mut out);
    out
}

/// Append non-overlapping left-to-right offsets of `pattern` in `data` into `out`.
#[inline]
pub fn scan_multibyte_delimiters_scalar_into(data: &[u8], pattern: &[u8], out: &mut Vec<usize>) {
    let m = pattern.len();
    if m == 0 || data.len() < m {
        return;
    }
    if m == 1 {
        scan_delimiters_scalar_into(data, pattern[0], out);
        return;
    }
    let first = pattern[0];
    let limit = data.len() - m;
    let mut idx = 0usize;
    while idx <= limit {
        if data[idx] == first && &data[idx..idx + m] == pattern {
            out.push(idx);
            idx += m;
        } else {
            idx += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_handles_empty_and_single_byte() {
        assert_eq!(scan_delimiters_scalar(b"", b'\n'), Vec::<usize>::new());
        assert_eq!(scan_delimiters_scalar(b"\n", b'\n'), vec![0]);
        assert_eq!(scan_delimiters_scalar(b"a", b'\n'), Vec::<usize>::new());
        assert_eq!(count_delimiters_scalar(b"\x00a\x00", b'\0'), 2);
    }

    #[test]
    fn scalar_multibyte_is_non_overlapping() {
        assert_eq!(scan_multibyte_delimiters_scalar(b"ababa", b"aba"), vec![0]);
        assert_eq!(
            scan_multibyte_delimiters_scalar(b"a||||b||", b"||"),
            vec![1, 3, 6]
        );
        assert_eq!(
            scan_multibyte_delimiters_scalar(b"abc", b""),
            Vec::<usize>::new()
        );
        assert_eq!(
            scan_multibyte_delimiters_scalar(b"a", b"ab"),
            Vec::<usize>::new()
        );
    }
}
