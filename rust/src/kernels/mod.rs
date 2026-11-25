//! LogForge Native Kernel Evolution Ladder (`kintsugi_core::kernels`).

pub mod bench;
pub mod byte_scanner;
#[cfg(feature = "logforge")]
pub mod logforge;
pub mod prefilter_tables;
pub mod rule_prefilter;
pub mod scalar;
pub mod sha256_hw;
pub mod streaming;

pub use bench::*;
pub use byte_scanner::{
    active_simd_backend, count_delimiters, scan_delimiters, scan_delimiters_into,
    scan_delimiters_with_backend, scan_multibyte_delimiters, scan_multibyte_delimiters_into,
};
#[cfg(feature = "logforge")]
pub use logforge::*;
pub use rule_prefilter::{
    active_prefilter_backend, builtin_rule_prefilter, cached_prefilter_backend,
    fold_confusables_for_pi, ks014_line_may_match, pi_flags_can_trigger, pi_keyword_prefilter,
    pi_line_flags, LiteralSpec, PrefilterBackend, PrefilterStats, RulePrefilter, PI_ASSET,
    PI_CHATML, PI_DEST, PI_EXFIL_INTENT, PI_EXFIL_VERB, PI_IGNORE, PI_INSTRUCTIONS,
    PI_NULLIFY_VERDICT, PI_OVERRIDE_OR_NEW, PI_SCOPE_NOUN, PI_SIMPLE_EXFIL,
};
pub use scalar::{
    count_delimiters_scalar, scan_delimiters_scalar, scan_multibyte_delimiters_scalar,
};
pub use sha256_hw::{
    active_sha256_backend, digest_to_hex_into, run_sha256_benchmark, sha256_bytes,
    sha256_bytes_scalar, sha256_bytes_with_mode, sha256_hex_fast, sha256_hex_into,
    sha256_hex_with_mode, Sha256BenchReport, Sha256BenchStats,
};
pub use streaming::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_matches_whole_buffer_across_arbitrary_splits() {
        let data = b"alpha||beta||||gamma||delta||eps";
        let expected = scan_multibyte_delimiters(data, b"||", false);
        for chunk_sz in [1usize, 2, 3, 5, 7, 13, 32] {
            for disable_simd in [false, true] {
                let mut scanner = StreamingByteScanner::new(b"||".to_vec(), disable_simd);
                let mut got = Vec::new();
                for chunk in data.chunks(chunk_sz) {
                    got.extend(scanner.push_chunk(chunk));
                }
                assert_eq!(got, expected, "chunk_sz={chunk_sz} disable_simd={disable_simd}");
                assert_eq!(scanner.bytes_processed(), data.len());
            }
        }
    }

    #[cfg(feature = "logforge")]
    #[test]
    fn timestamp_and_jsonl_normalization_preserves_precision_and_raw() {
        assert_eq!(
            normalize_timestamp_utc("2026-11-21T18:26:00.123456+07:00").as_deref(),
            Some("2026-11-21T11:26:00.123456Z")
        );
        assert_eq!(
            normalize_timestamp_utc("1795266360123456").as_deref(),
            Some("2026-11-21T13:06:00.123456Z")
        );
        assert_eq!(
            normalize_timestamp_utc("1795266360.987654321").as_deref(),
            Some("2026-11-21T13:06:00.987654321Z")
        );
        let payload = concat!(
            "{\"timestamp\":\"2026-11-21T18:26:00.500+07:00\",\"level\":\"warn\",\"message\":\"ok\"}\n",
            "2026-11-21 11:26:01Z ERROR disk full\n",
            "plain text line\n",
            "{\"timestamp\":\"2026-11-21T00:00:00Z\",\"level\":\"info\",\"message\":\"hi \\uD83D\\uDE80!\"}\n"
        )
        .as_bytes();
        let events = normalize_log_records(payload, b'\n', false);
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].format, "jsonl");
        assert_eq!(events[0].timestamp_utc.as_deref(), Some("2026-11-21T11:26:00.5Z"));
        assert_eq!(events[0].level.as_deref(), Some("WARN"));
        assert_eq!(events[1].format, "structured");
        assert_eq!(events[1].level.as_deref(), Some("ERROR"));
        assert_eq!(events[1].message.as_deref(), Some("disk full"));
        assert_eq!(events[2].format, "raw");
        assert_eq!(events[2].raw_preserved, "plain text line");
        assert_eq!(events[3].message.as_deref(), Some("hi 🚀!"));
    }
}
