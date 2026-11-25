//! Streaming Multi-Chunk Delimiter Scanner (`kintsugi_core::kernels::streaming`).
//!
//! Preserves exact global byte offsets across arbitrary chunk splits while reusing internal
//! scratch buffers (`work_buf` and `local_matches`) for zero per-chunk heap allocations once warmed up.

use crate::kernels::byte_scanner::{
    active_simd_backend, scan_delimiters_into, scan_multibyte_delimiters_into,
};

/// Streaming delimiter scanner that preserves exact global byte offsets across arbitrary chunk splits.
#[derive(Debug, Clone)]
pub struct StreamingByteScanner {
    pattern: Vec<u8>,
    disable_simd: bool,
    global_offset: usize,
    tail: Vec<u8>,
    tail_start: usize,
    work_buf: Vec<u8>,
    local_matches: Vec<usize>,
}

impl StreamingByteScanner {
    /// Construct a new streaming scanner for single-byte or multi-byte `pattern`.
    pub fn new(pattern: Vec<u8>, disable_simd: bool) -> Self {
        Self {
            pattern,
            disable_simd,
            global_offset: 0,
            tail: Vec::new(),
            tail_start: 0,
            work_buf: Vec::new(),
            local_matches: Vec::new(),
        }
    }

    /// Return the active kernel backend string.
    #[inline]
    pub fn backend(&self) -> &'static str {
        active_simd_backend(self.disable_simd)
    }

    /// Total bytes fed so far across all chunks.
    #[inline]
    pub fn bytes_processed(&self) -> usize {
        self.global_offset
    }

    /// Feed the next arbitrary-length `chunk` and append exact global byte offsets of new matches into `out`.
    pub fn push_chunk_into(&mut self, chunk: &[u8], out: &mut Vec<usize>) {
        if chunk.is_empty() {
            return;
        }
        if self.pattern.is_empty() {
            self.global_offset += chunk.len();
            self.tail_start = self.global_offset;
            return;
        }

        let m = self.pattern.len();
        if m == 1 {
            let delim = self.pattern[0];
            let base_out_len = out.len();
            scan_delimiters_into(chunk, delim, self.disable_simd, out);
            let base = self.global_offset;
            if base != 0 {
                for off in &mut out[base_out_len..] {
                    *off += base;
                }
            }
            self.global_offset += chunk.len();
            self.tail_start = self.global_offset;
            return;
        }

        self.work_buf.clear();
        self.work_buf.reserve(self.tail.len() + chunk.len());
        self.work_buf.extend_from_slice(&self.tail);
        self.work_buf.extend_from_slice(chunk);

        self.local_matches.clear();
        scan_multibyte_delimiters_into(
            &self.work_buf,
            &self.pattern,
            self.disable_simd,
            &mut self.local_matches,
        );
        out.reserve(self.local_matches.len());
        for &off in &self.local_matches {
            out.push(self.tail_start + off);
        }

        let last_consumed = self.local_matches.last().map(|o| o + m).unwrap_or(0);
        let keep_from = last_consumed.max(self.work_buf.len().saturating_sub(m - 1));
        self.tail.clear();
        self.tail.extend_from_slice(&self.work_buf[keep_from..]);
        self.tail_start += keep_from;
        self.global_offset += chunk.len();
    }

    /// Feed the next arbitrary-length `chunk` and return exact global byte offsets of new matches.
    pub fn push_chunk(&mut self, chunk: &[u8]) -> Vec<usize> {
        let mut out = Vec::new();
        self.push_chunk_into(chunk, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernels::byte_scanner::{scan_delimiters, scan_multibyte_delimiters};

    #[test]
    fn streaming_push_chunk_into_reuses_buffers_and_matches_whole_buffer() {
        let data = b"alpha||beta||||gamma||delta||eps\nline2\nline3";
        let expected_mb = scan_multibyte_delimiters(data, b"||", false);
        let expected_sb = scan_delimiters(data, b'\n', false);

        for chunk_sz in [1usize, 2, 3, 5, 7, 13, 32] {
            for disable_simd in [false, true] {
                let mut mb = StreamingByteScanner::new(b"||".to_vec(), disable_simd);
                let mut got_mb = Vec::new();
                for chunk in data.chunks(chunk_sz) {
                    mb.push_chunk_into(chunk, &mut got_mb);
                }
                assert_eq!(got_mb, expected_mb, "mb chunk_sz={chunk_sz}");
                assert_eq!(mb.bytes_processed(), data.len());

                let mut sb = StreamingByteScanner::new(vec![b'\n'], disable_simd);
                let mut got_sb = Vec::new();
                for chunk in data.chunks(chunk_sz) {
                    sb.push_chunk_into(chunk, &mut got_sb);
                }
                assert_eq!(got_sb, expected_sb, "sb chunk_sz={chunk_sz}");
                assert_eq!(sb.bytes_processed(), data.len());
            }
        }
    }

    #[test]
    fn empty_pattern_still_advances_global_offset() {
        let mut scanner = StreamingByteScanner::new(Vec::new(), false);
        assert!(scanner.push_chunk(b"hello ").is_empty());
        assert_eq!(scanner.bytes_processed(), 6);
        let mut out = Vec::new();
        scanner.push_chunk_into(b"world", &mut out);
        assert!(out.is_empty());
        assert_eq!(scanner.bytes_processed(), 11);
    }
}
