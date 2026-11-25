// kintsugi: ignore-file
//! Canonical Unicode Security Policy (`KS-019`, `@KML/1`, `DynamicRuleRegistry`, `PreToolUse`).
//!
//! Single source of truth for Trojan Source bidirectional overrides/isolates,
//! Arabic Letter Mark (`U+061C`), zero-width token-smuggling characters, and
//! mid-stream `U+FEFF` BOM smuggling, together with exact UTF-8 byte sequences
//! consumed by `kernels::prefilter_tables::builtin_rule_prefilter`.

/// Exact UTF-8 byte sequences for every security-relevant Unicode control codepoint:
/// - `U+061C` (`\xD8\x9C`) Arabic Letter Mark
/// - `U+200B..=U+200F` (`\xE2\x80\x8B`..`\xE2\x80\x8F`) ZWSP, ZWNJ, ZWJ, LRM, RLM
/// - `U+202A..=U+202E` (`\xE2\x80\xAA`..`\xE2\x80\xAE`) LRE, RLE, PDF, LRO, RLO
/// - `U+2060` (`\xE2\x81\xA0`) Word Joiner
/// - `U+2066..=U+2069` (`\xE2\x81\xA6`..`\xE2\x81\xA9`) LRI, RLI, FSI, PDI
/// - `U+FEFF` (`\xEF\xBB\xBF`) Zero Width No-Break Space / BOM
pub const TROJAN_UTF8_SEQUENCES: &[&[u8]] = &[
    b"\xD8\x9C",
    b"\xE2\x80\x8B",
    b"\xE2\x80\x8C",
    b"\xE2\x80\x8D",
    b"\xE2\x80\x8E",
    b"\xE2\x80\x8F",
    b"\xE2\x80\xAA",
    b"\xE2\x80\xAB",
    b"\xE2\x80\xAC",
    b"\xE2\x80\xAD",
    b"\xE2\x80\xAE",
    b"\xE2\x81\xA0",
    b"\xE2\x81\xA6",
    b"\xE2\x81\xA7",
    b"\xE2\x81\xA8",
    b"\xE2\x81\xA9",
    b"\xEF\xBB\xBF",
];

/// Structured verdict from `evaluate_unicode_security` identifying the exact first violating byte offset and class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnicodeSecurityDecision {
    pub has_violation: bool,
    pub first_byte_offset: Option<usize>,
    /// One of `"trojan_bidi"`, `"zero_width_smuggling"`, or `"mid_stream_bom"` when `has_violation` is `true`.
    pub category: Option<&'static str>,
}

/// Returns `true` if `c` is a Trojan Source bidirectional control character:
/// `U+202A..=U+202E`, `U+2066..=U+2069`, `U+200E`, `U+200F`, or `U+061C`.
#[inline]
pub fn is_trojan_bidi_char(c: char) -> bool {
    matches!(
        c as u32,
        0x061C | 0x200E | 0x200F | 0x202A..=0x202E | 0x2066..=0x2069
    )
}

/// Returns `true` if `c` is an invisible zero-width token-smuggling character:
/// `U+200B..=U+200D` (ZWSP, ZWNJ, ZWJ) or `U+2060` (Word Joiner).
#[inline]
pub fn is_zero_width_smuggling_char(c: char) -> bool {
    matches!(c as u32, 0x200B..=0x200D | 0x2060)
}

/// Evaluate `s` for Trojan Source Bidi controls, zero-width smuggling characters, and
/// non-file-initial `U+FEFF` BOM (`allow_file_start_bom` permits `U+FEFF` ONLY at byte offset `0`).
#[inline]
pub fn evaluate_unicode_security(s: &str, allow_file_start_bom: bool) -> UnicodeSecurityDecision {
    if s.is_ascii() {
        return UnicodeSecurityDecision { has_violation: false, first_byte_offset: None, category: None };
    }
    for (byte_idx, c) in s.char_indices() {
        if is_trojan_bidi_char(c) {
            return UnicodeSecurityDecision {
                has_violation: true,
                first_byte_offset: Some(byte_idx),
                category: Some("trojan_bidi"),
            };
        }
        if is_zero_width_smuggling_char(c) {
            return UnicodeSecurityDecision {
                has_violation: true,
                first_byte_offset: Some(byte_idx),
                category: Some("zero_width_smuggling"),
            };
        }
        if c == '\u{FEFF}' && !(allow_file_start_bom && byte_idx == 0) {
            return UnicodeSecurityDecision {
                has_violation: true,
                first_byte_offset: Some(byte_idx),
                category: Some("mid_stream_bom"),
            };
        }
    }
    UnicodeSecurityDecision { has_violation: false, first_byte_offset: None, category: None }
}

/// Returns `true` if `s` violates the canonical Unicode security policy (delegates to `evaluate_unicode_security`).
#[inline]
pub fn contains_security_unicode_control(s: &str, allow_file_start_bom: bool) -> bool {
    evaluate_unicode_security(s, allow_file_start_bom).has_violation
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trojan_utf8_sequences_stay_100_percent_synchronized_with_char_predicates() {
        let mut matched_utf8: Vec<Vec<u8>> = Vec::new();
        for cp in 0u32..=0x10FFFF {
            let Some(ch) = char::from_u32(cp) else { continue };
            if is_trojan_bidi_char(ch) || is_zero_width_smuggling_char(ch) || ch == '\u{FEFF}' {
                let mut buf = [0u8; 4];
                matched_utf8.push(ch.encode_utf8(&mut buf).as_bytes().to_vec());
            }
        }
        let table: Vec<Vec<u8>> = TROJAN_UTF8_SEQUENCES.iter().map(|s| s.to_vec()).collect();
        assert_eq!(matched_utf8.len(), 17);
        assert_eq!(matched_utf8, table);
    }

    #[test]
    fn evaluate_unicode_security_reports_exact_offsets_and_categories() {
        assert_eq!(
            evaluate_unicode_security("\u{FEFF}fn main() {}", true),
            UnicodeSecurityDecision { has_violation: false, first_byte_offset: None, category: None }
        );
        assert_eq!(
            evaluate_unicode_security("\u{FEFF}fn main() {}", false),
            UnicodeSecurityDecision { has_violation: true, first_byte_offset: Some(0), category: Some("mid_stream_bom") }
        );
        assert_eq!(
            evaluate_unicode_security("let x = \"a\u{FEFF}b\";", true),
            UnicodeSecurityDecision { has_violation: true, first_byte_offset: Some(10), category: Some("mid_stream_bom") }
        );
        assert_eq!(
            evaluate_unicode_security("role = 'user\u{061C}'", true),
            UnicodeSecurityDecision { has_violation: true, first_byte_offset: Some(12), category: Some("trojan_bidi") }
        );
        assert_eq!(
            evaluate_unicode_security("id\u{200B}ent = 1", true),
            UnicodeSecurityDecision { has_violation: true, first_byte_offset: Some(2), category: Some("zero_width_smuggling") }
        );
        let benign = "Báo cáo kỹ thuật — độ trễ giảm 4× … kết quả chuẩn → đạt!";
        assert!(!contains_security_unicode_control(benign, false));
        assert!(!contains_security_unicode_control(benign, true));
    }
}
