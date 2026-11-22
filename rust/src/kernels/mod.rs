//! LogForge Native Kernel Evolution Ladder (`kintsugi_core::kernels`).
//!
//! Provides:
//! - Tier 2: Safe Rust scalar reference (`scalar`)
//! - Tier 3: Architecture-accelerated SIMD intrinsics (`byte_scanner`: AArch64 NEON & x86_64 AVX2)
//!   with explicit `disable_simd` override for independent fallback testing
//! - Streaming multi-chunk delimiter scanner (`StreamingByteScanner`)
//! - Zero-loss timestamp (`normalize_timestamp_utc`) & JSONL/structured-log event normalizer
//! - Reproducible in-process benchmark harness (`run_logforge_benchmark`)

pub mod byte_scanner;
pub mod rule_prefilter;
pub mod scalar;
pub mod sha256_hw;

pub use byte_scanner::{
    active_simd_backend, count_delimiters, scan_delimiters, scan_delimiters_into,
    scan_delimiters_with_backend, scan_multibyte_delimiters, scan_multibyte_delimiters_into,
};
pub use rule_prefilter::{
    active_prefilter_backend, builtin_rule_prefilter, ks014_line_may_match, pi_flags_can_trigger,
    pi_keyword_prefilter, pi_line_flags, LiteralSpec, RulePrefilter,
};
pub use scalar::{
    count_delimiters_scalar, scan_delimiters_scalar, scan_multibyte_delimiters_scalar,
};
pub use sha256_hw::{
    active_sha256_backend, run_sha256_benchmark, sha256_bytes, sha256_bytes_scalar,
    sha256_bytes_with_mode, sha256_hex_fast, sha256_hex_into, sha256_hex_with_mode,
    Sha256BenchReport, Sha256BenchStats,
};

use std::hint::black_box;
use std::time::Instant;

use crate::json_escape;

/// Streaming delimiter scanner that preserves exact global byte offsets across arbitrary chunk splits.
#[derive(Debug, Clone)]
pub struct StreamingByteScanner {
    pattern: Vec<u8>,
    disable_simd: bool,
    global_offset: usize,
    tail: Vec<u8>,
    tail_start: usize,
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
        }
    }

    /// Return the active kernel backend string.
    pub fn backend(&self) -> &'static str {
        active_simd_backend(self.disable_simd)
    }

    /// Total bytes fed so far across all chunks.
    pub fn bytes_processed(&self) -> usize {
        self.global_offset
    }

    /// Feed the next arbitrary-length `chunk` and return exact global byte offsets of new matches.
    pub fn push_chunk(&mut self, chunk: &[u8]) -> Vec<usize> {
        if chunk.is_empty() || self.pattern.is_empty() {
            return Vec::new();
        }
        let m = self.pattern.len();
        if m == 1 {
            let delim = self.pattern[0];
            let mut offsets = scan_delimiters(chunk, delim, self.disable_simd);
            let base = self.global_offset;
            for off in &mut offsets {
                *off += base;
            }
            self.global_offset += chunk.len();
            self.tail_start = self.global_offset;
            return offsets;
        }

        let mut work = Vec::with_capacity(self.tail.len() + chunk.len());
        work.extend_from_slice(&self.tail);
        work.extend_from_slice(chunk);

        let local_matches = scan_multibyte_delimiters(&work, &self.pattern, self.disable_simd);
        let mut global_matches = Vec::with_capacity(local_matches.len());
        for off in &local_matches {
            global_matches.push(self.tail_start + *off);
        }

        let last_consumed = local_matches.last().map(|o| o + m).unwrap_or(0);
        let keep_from = last_consumed.max(work.len().saturating_sub(m - 1));
        self.tail.clear();
        self.tail.extend_from_slice(&work[keep_from..]);
        self.tail_start += keep_from;
        self.global_offset += chunk.len();

        global_matches
    }
}

/// Normalized log event emitted by `LogForge` without dropping original payload data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedLogEvent {
    pub record_index: usize,
    pub byte_offset: usize,
    pub byte_len: usize,
    pub format: &'static str,
    pub timestamp_utc: Option<String>,
    pub timestamp_raw: Option<String>,
    pub level: Option<String>,
    pub message: Option<String>,
    pub raw_preserved: String,
}

impl NormalizedLogEvent {
    /// Serialize this event into deterministic JSON.
    pub fn to_json(&self) -> String {
        let ts_utc = match &self.timestamp_utc {
            Some(v) => format!("\"{}\"", json_escape(v)),
            None => "null".to_string(),
        };
        let ts_raw = match &self.timestamp_raw {
            Some(v) => format!("\"{}\"", json_escape(v)),
            None => "null".to_string(),
        };
        let lvl = match &self.level {
            Some(v) => format!("\"{}\"", json_escape(v)),
            None => "null".to_string(),
        };
        let msg = match &self.message {
            Some(v) => format!("\"{}\"", json_escape(v)),
            None => "null".to_string(),
        };
        format!(
            "{{\"record_index\":{},\"byte_offset\":{},\"byte_len\":{},\"format\":\"{}\",\"timestamp_utc\":{},\"timestamp_raw\":{},\"level\":{},\"message\":{},\"raw_preserved\":\"{}\"}}",
            self.record_index,
            self.byte_offset,
            self.byte_len,
            self.format,
            ts_utc,
            ts_raw,
            lvl,
            msg,
            json_escape(&self.raw_preserved),
        )
    }
}

/// Howard Hinnant civil-calendar conversion: days since 1970-01-01 from (Y, M, D).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = month as u64;
    let d = day as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + (doe as i64) - 719_468
}

/// Howard Hinnant inverse civil-calendar conversion: (year, month, day) from days since 1970-01-01.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m, d)
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn format_epoch_utc(epoch_secs: i64, frac_digits: &str) -> Option<String> {
    let days = epoch_secs.div_euclid(86_400);
    let rem = epoch_secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    if !(0..=9999).contains(&year) {
        return None;
    }
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    let clean_frac = frac_digits.trim_end_matches('0');
    if clean_frac.is_empty() {
        Some(format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
        ))
    } else {
        Some(format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{clean_frac}Z"
        ))
    }
}

fn parse_ascii_uint(bytes: &[u8]) -> Option<i64> {
    if bytes.is_empty() || !bytes.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    std::str::from_utf8(bytes).ok()?.parse::<i64>().ok()
}

/// Normalize ISO-8601 / RFC-3339 or Unix epoch timestamps into canonical UTC RFC-3339 without float precision loss.
pub fn normalize_timestamp_utc(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }

    // 1. Numeric Unix epoch (integer s/ms/us/ns or fractional secs.frac)
    if s.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        if let Some((sec_part, frac_part)) = s.split_once('.') {
            if sec_part.is_empty() || frac_part.is_empty() || frac_part.contains('.') {
                return None;
            }
            let secs = sec_part.parse::<i64>().ok()?;
            return format_epoch_utc(secs, frac_part);
        }
        let val = s.parse::<i128>().ok()?;
        let digits = s.len();
        let (secs, frac): (i64, String) = if digits >= 18 {
            let sec = (val / 1_000_000_000) as i64;
            let ns = (val % 1_000_000_000) as u64;
            (sec, format!("{ns:09}"))
        } else if (15..=17).contains(&digits) {
            let sec = (val / 1_000_000) as i64;
            let us = (val % 1_000_000) as u64;
            (sec, format!("{us:06}"))
        } else if (12..=14).contains(&digits) {
            let sec = (val / 1_000) as i64;
            let ms = (val % 1_000) as u64;
            (sec, format!("{ms:03}"))
        } else {
            (val as i64, String::new())
        };
        return format_epoch_utc(secs, &frac);
    }

    // 2. ISO-8601 / RFC-3339: YYYY-MM-DD[T|t| ]HH:MM:SS([.,]frac)?(Z|z|[+-]HH:?MM)?
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || (b[10] != b'T' && b[10] != b't' && b[10] != b' ') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let year = parse_ascii_uint(&b[0..4])?;
    let month = parse_ascii_uint(&b[5..7])? as u32;
    let day = parse_ascii_uint(&b[8..10])? as u32;
    let hour = parse_ascii_uint(&b[11..13])?;
    let minute = parse_ascii_uint(&b[14..16])?;
    let second = parse_ascii_uint(&b[17..19])?;

    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    if !(0..=23).contains(&hour) || !(0..=59).contains(&minute) || !(0..=59).contains(&second) {
        return None;
    }

    let mut cursor = 19usize;
    let mut frac = "";
    if cursor < b.len() && (b[cursor] == b'.' || b[cursor] == b',') {
        cursor += 1;
        let frac_start = cursor;
        while cursor < b.len() && b[cursor].is_ascii_digit() {
            cursor += 1;
        }
        if cursor == frac_start {
            return None;
        }
        frac = &s[frac_start..cursor];
    }

    let tz_offset_secs: i64 = if cursor == b.len() {
        0
    } else {
        let tz = &s[cursor..];
        if tz == "Z" || tz == "z" {
            0
        } else {
            let tb = tz.as_bytes();
            let sign: i64 = match tb.first().copied() {
                Some(b'+') => 1,
                Some(b'-') => -1,
                _ => return None,
            };
            let rest = &tb[1..];
            let (oh, om) = if rest.len() == 5 && rest[2] == b':' {
                (parse_ascii_uint(&rest[0..2])?, parse_ascii_uint(&rest[3..5])?)
            } else if rest.len() == 4 {
                (parse_ascii_uint(&rest[0..2])?, parse_ascii_uint(&rest[2..4])?)
            } else if rest.len() == 2 {
                (parse_ascii_uint(&rest[0..2])?, 0)
            } else {
                return None;
            };
            if !(0..=23).contains(&oh) || !(0..=59).contains(&om) {
                return None;
            }
            sign * (oh * 3600 + om * 60)
        }
    };

    let days = days_from_civil(year, month, day);
    let local_secs = days * 86_400 + hour * 3600 + minute * 60 + second;
    let utc_secs = local_secs - tz_offset_secs;
    format_epoch_utc(utc_secs, frac)
}

fn canonicalize_level(raw: &str) -> Option<String> {
    let up = raw.trim().to_ascii_uppercase();
    match up.as_str() {
        "TRACE" | "TRC" => Some("TRACE".to_string()),
        "DEBUG" | "DBG" => Some("DEBUG".to_string()),
        "INFO" | "INF" | "INFORMATION" => Some("INFO".to_string()),
        "WARN" | "WARNING" | "WRN" => Some("WARN".to_string()),
        "ERROR" | "ERR" => Some("ERROR".to_string()),
        "FATAL" | "CRIT" | "CRITICAL" | "PANIC" => Some("CRITICAL".to_string()),
        _ => None,
    }
}

fn parse_json_string(bytes: &[u8], mut i: usize) -> Option<(String, usize)> {
    if i >= bytes.len() || bytes[i] != b'"' {
        return None;
    }
    i += 1;
    let mut out = String::new();
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' {
            return Some((out, i + 1));
        }
        if b == b'\\' {
            i += 1;
            if i >= bytes.len() {
                return None;
            }
            match bytes[i] {
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'/' => out.push('/'),
                b'b' => out.push('\u{0008}'),
                b'f' => out.push('\u{000C}'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                b'u' => {
                    if i + 4 >= bytes.len() {
                        return None;
                    }
                    let hex_str = std::str::from_utf8(&bytes[i + 1..i + 5]).ok()?;
                    let code = u16::from_str_radix(hex_str, 16).ok()?;
                    if (0xD800..=0xDBFF).contains(&code) {
                        if i + 10 < bytes.len() && bytes[i + 5] == b'\\' && bytes[i + 6] == b'u' {
                            let lo_str = std::str::from_utf8(&bytes[i + 7..i + 11]).ok()?;
                            let lo = u16::from_str_radix(lo_str, 16).ok()?;
                            if (0xDC00..=0xDFFF).contains(&lo) {
                                let cp = 0x10000
                                    + ((((code as u32) - 0xD800) << 10) | ((lo as u32) - 0xDC00));
                                if let Some(ch) = char::from_u32(cp) {
                                    out.push(ch);
                                }
                                i += 6;
                            }
                        }
                    } else if let Some(ch) = char::from_u32(code as u32) {
                        out.push(ch);
                    }
                    i += 4;
                }
                other => out.push(other as char),
            }
            i += 1;
        } else {
            let s = std::str::from_utf8(&bytes[i..]).ok()?;
            let ch = s.chars().next()?;
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    None
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

fn skip_json_value(bytes: &[u8], mut i: usize) -> Option<usize> {
    i = skip_ws(bytes, i);
    if i >= bytes.len() {
        return None;
    }
    match bytes[i] {
        b'"' => {
            let (_, next) = parse_json_string(bytes, i)?;
            Some(next)
        }
        b'{' | b'[' => {
            let mut depth = 0usize;
            while i < bytes.len() {
                match bytes[i] {
                    b'"' => {
                        let (_, next) = parse_json_string(bytes, i)?;
                        i = next;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            return Some(i + 1);
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            None
        }
        _ => {
            while i < bytes.len() && !matches!(bytes[i], b',' | b'}' | b']') && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            Some(i)
        }
    }
}

/// Extract top-level scalar string/number fields from a JSON object line without mutating raw content.
fn extract_jsonl_fields(trimmed: &str) -> Option<Vec<(String, String)>> {
    let bytes = trimmed.as_bytes();
    let mut i = skip_ws(bytes, 0);
    if i >= bytes.len() || bytes[i] != b'{' {
        return None;
    }
    i += 1;
    let mut pairs = Vec::new();
    loop {
        i = skip_ws(bytes, i);
        if i >= bytes.len() {
            return None;
        }
        if bytes[i] == b'}' {
            i = skip_ws(bytes, i + 1);
            return if i == bytes.len() { Some(pairs) } else { None };
        }
        if bytes[i] == b',' {
            i += 1;
            continue;
        }
        if bytes[i] != b'"' {
            return None;
        }
        let (key, next_k) = parse_json_string(bytes, i)?;
        i = skip_ws(bytes, next_k);
        if i >= bytes.len() || bytes[i] != b':' {
            return None;
        }
        i = skip_ws(bytes, i + 1);
        if i >= bytes.len() {
            return None;
        }
        if bytes[i] == b'"' {
            let (val, next_v) = parse_json_string(bytes, i)?;
            pairs.push((key, val));
            i = next_v;
        } else if bytes[i] == b'{' || bytes[i] == b'[' {
            i = skip_json_value(bytes, i)?;
        } else {
            let val_start = i;
            let next_v = skip_json_value(bytes, i)?;
            let raw_scalar = trimmed[val_start..next_v].trim();
            if !raw_scalar.is_empty() && raw_scalar != "null" {
                pairs.push((key, raw_scalar.to_string()));
            }
            i = next_v;
        }
    }
}

fn parse_logfmt_pairs(trimmed: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = trimmed.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let token_start = i;
        while i < bytes.len() && bytes[i] != b'=' && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'=' && i > token_start {
            let key = &trimmed[token_start..i];
            i += 1;
            if i < bytes.len() && bytes[i] == b'"' {
                if let Some((val, next)) = parse_json_string(bytes, i) {
                    out.push((key.to_string(), val));
                    i = next;
                    continue;
                }
            }
            let val_start = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            out.push((key.to_string(), trimmed[val_start..i].to_string()));
        } else {
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
        }
    }
    out
}

/// Normalize a single decoded log record line while preserving `raw_preserved` verbatim.
pub fn normalize_single_record(
    record_index: usize,
    byte_offset: usize,
    byte_len: usize,
    raw_line: &str,
) -> NormalizedLogEvent {
    let trimmed = raw_line.trim();
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        if let Some(pairs) = extract_jsonl_fields(trimmed) {
            let mut ts_raw: Option<String> = None;
            let mut level: Option<String> = None;
            let mut message: Option<String> = None;
            for (k, v) in pairs {
                let kl = k.to_ascii_lowercase();
                if ts_raw.is_none()
                    && matches!(kl.as_str(), "timestamp" | "ts" | "time" | "@timestamp" | "created_at")
                {
                    ts_raw = Some(v);
                } else if level.is_none()
                    && matches!(kl.as_str(), "level" | "severity" | "lvl" | "log_level")
                {
                    level = canonicalize_level(&v).or(Some(v.to_ascii_uppercase()));
                } else if message.is_none()
                    && matches!(kl.as_str(), "message" | "msg" | "event" | "error")
                {
                    message = Some(v);
                }
            }
            let ts_utc = ts_raw.as_deref().and_then(normalize_timestamp_utc);
            return NormalizedLogEvent {
                record_index,
                byte_offset,
                byte_len,
                format: "jsonl",
                timestamp_utc: ts_utc,
                timestamp_raw: ts_raw,
                level,
                message,
                raw_preserved: raw_line.to_string(),
            };
        }
    }

    // Check key=value structured logfmt
    let kv_pairs = parse_logfmt_pairs(trimmed);
    if !kv_pairs.is_empty() {
        let mut ts_raw: Option<String> = None;
        let mut level: Option<String> = None;
        let mut message: Option<String> = None;
        for (k, v) in &kv_pairs {
            let kl = k.to_ascii_lowercase();
            if ts_raw.is_none() && matches!(kl.as_str(), "ts" | "time" | "timestamp" | "@timestamp")
            {
                ts_raw = Some(v.clone());
            } else if level.is_none() && matches!(kl.as_str(), "level" | "lvl" | "severity") {
                level = canonicalize_level(v).or_else(|| Some(v.to_ascii_uppercase()));
            } else if message.is_none() && matches!(kl.as_str(), "msg" | "message" | "event") {
                message = Some(v.clone());
            }
        }
        if ts_raw.is_some() || level.is_some() || message.is_some() {
            // Also check leading timestamp token if ts key omitted
            if ts_raw.is_none() {
                if let Some(first_tok) = trimmed.split_whitespace().next() {
                    let clean_tok = first_tok.trim_matches(|c| c == '[' || c == ']');
                    if normalize_timestamp_utc(clean_tok).is_some() {
                        ts_raw = Some(clean_tok.to_string());
                    }
                }
            }
            let ts_utc = ts_raw.as_deref().and_then(normalize_timestamp_utc);
            return NormalizedLogEvent {
                record_index,
                byte_offset,
                byte_len,
                format: "structured",
                timestamp_utc: ts_utc,
                timestamp_raw: ts_raw,
                level,
                message,
                raw_preserved: raw_line.to_string(),
            };
        }
    }

    // Check `[TS] LEVEL message` or `TS LEVEL message` (including `YYYY-MM-DD HH:MM:SS...`)
    let mut tokens = trimmed.split_whitespace();
    if let Some(first) = tokens.next() {
        let clean_first = first.trim_matches(|c| c == '[' || c == ']');
        let mut matched_ts: Option<(String, String, usize)> = normalize_timestamp_utc(clean_first)
            .and_then(|utc| {
                trimmed
                    .find(first)
                    .map(|p| (utc, clean_first.to_string(), p + first.len()))
            });

        if matched_ts.is_none() && clean_first.len() == 10 && clean_first.as_bytes()[4] == b'-' && clean_first.as_bytes()[7] == b'-' {
            if let Some(second_tok) = tokens.next() {
                let clean_second = second_tok.trim_matches(|c| c == '[' || c == ']');
                let combined = format!("{clean_first} {clean_second}");
                if let Some(utc) = normalize_timestamp_utc(&combined) {
                    if let Some(p1) = trimmed.find(first) {
                        let search_from = p1 + first.len();
                        if let Some(rel2) = trimmed[search_from..].find(second_tok) {
                            matched_ts = Some((utc, combined, search_from + rel2 + second_tok.len()));
                        }
                    }
                }
            }
        }

        if let Some((ts_utc, ts_raw, after_ts_idx)) = matched_ts {
            let after_ts = trimmed[after_ts_idx..].trim_start();
            let mut rest_tokens = after_ts.split_whitespace();
            let next_tok = rest_tokens.next();
            let lvl = next_tok.and_then(canonicalize_level);
            let msg_start = if let (Some(_), Some(lvl_tok)) = (&lvl, next_tok) {
                if let Some(pos) = after_ts.find(lvl_tok) {
                    after_ts[pos + lvl_tok.len()..].trim_start().to_string()
                } else {
                    String::new()
                }
            } else {
                after_ts.to_string()
            };
            return NormalizedLogEvent {
                record_index,
                byte_offset,
                byte_len,
                format: "structured",
                timestamp_utc: Some(ts_utc),
                timestamp_raw: Some(ts_raw),
                level: lvl,
                message: if msg_start.is_empty() {
                    None
                } else {
                    Some(msg_start)
                },
                raw_preserved: raw_line.to_string(),
            };
        }
    }

    NormalizedLogEvent {
        record_index,
        byte_offset,
        byte_len,
        format: "raw",
        timestamp_utc: None,
        timestamp_raw: None,
        level: None,
        message: Some(raw_line.to_string()),
        raw_preserved: raw_line.to_string(),
    }
}

/// Split `data` on `delim` using the selected SIMD/scalar backend and normalize each non-empty record.
pub fn normalize_log_records(
    data: &[u8],
    delim: u8,
    disable_simd: bool,
) -> Vec<NormalizedLogEvent> {
    let offsets = scan_delimiters(data, delim, disable_simd);
    let mut events = Vec::new();
    let mut start = 0usize;
    let mut record_index = 0usize;

    let mut push_slice = |slice_start: usize, slice_end: usize| {
        let mut raw_slice = &data[slice_start..slice_end];
        if delim == b'\n' && raw_slice.ends_with(b"\r") {
            raw_slice = &raw_slice[..raw_slice.len() - 1];
        }
        if raw_slice.is_empty() {
            return;
        }
        let raw_line = String::from_utf8_lossy(raw_slice).into_owned();
        if raw_line.trim().is_empty() {
            return;
        }
        events.push(normalize_single_record(
            record_index,
            slice_start,
            raw_slice.len(),
            &raw_line,
        ));
        record_index += 1;
    };

    for off in offsets {
        push_slice(start, off);
        start = off + 1;
    }
    if start < data.len() {
        push_slice(start, data.len());
    }
    events
}

/// Benchmark metrics summary for a single kernel execution tier.
#[derive(Debug, Clone)]
pub struct KernelBenchStats {
    pub tier: &'static str,
    pub backend: &'static str,
    pub min_us: f64,
    pub median_us: f64,
    pub p95_us: f64,
    pub mean_us: f64,
    pub throughput_gbps: f64,
    pub matches: usize,
}

/// Complete reproducible benchmark result produced by `run_logforge_benchmark`.
#[derive(Debug, Clone)]
pub struct LogForgeBenchReport {
    pub arch: &'static str,
    pub os: &'static str,
    pub size_bytes: usize,
    pub warmup: usize,
    pub iters: usize,
    pub seed: u64,
    pub delim: u8,
    pub parity_ok: bool,
    pub scalar: KernelBenchStats,
    pub simd: KernelBenchStats,
    pub simd_reused_buf: KernelBenchStats,
    pub simd_fallback: KernelBenchStats,
    pub multibyte_scalar: KernelBenchStats,
    pub multibyte_simd: KernelBenchStats,
    pub speedup_simd_vs_scalar: f64,
}

fn generate_synthetic_log_buffer(size_bytes: usize, seed: u64, delim: u8) -> Vec<u8> {
    let templates: [&[u8]; 4] = [
        b"{\"timestamp\":\"2026-11-21T18:26:00.123456+07:00\",\"level\":\"info\",\"message\":\"gateway request accepted\",\"latency_us\":42}",
        b"2026-11-21 18:26:01.005Z WARN stream chunk alignment verified||ok",
        b"ts=1795266362.500 level=error msg=\"retry backoff\" host=node-01",
        b"{\"ts\":1795266363123456,\"severity\":\"debug\",\"event\":\"heartbeat\",\"ok\":true}",
    ];
    let mut state = if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed };
    let mut out = Vec::with_capacity(size_bytes);
    while out.len() < size_bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let line = templates[(state as usize) & 3];
        let remaining = size_bytes - out.len();
        if remaining > line.len() {
            out.extend_from_slice(line);
            out.push(delim);
        } else {
            out.extend_from_slice(&line[..remaining]);
        }
    }
    out
}

fn compute_stats(
    tier: &'static str,
    backend: &'static str,
    mut samples_us: Vec<f64>,
    size_bytes: usize,
    matches: usize,
) -> KernelBenchStats {
    samples_us.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = samples_us.len().max(1);
    let min_us = samples_us[0];
    let median_us = if n % 2 == 1 {
        samples_us[n / 2]
    } else {
        0.5 * (samples_us[n / 2 - 1] + samples_us[n / 2])
    };
    let p95_idx = ((n as f64) * 0.95).ceil() as usize;
    let p95_us = samples_us[p95_idx.saturating_sub(1).min(n - 1)];
    let mean_us = samples_us.iter().sum::<f64>() / (n as f64);
    let secs = median_us * 1e-6;
    let throughput_gbps = if secs > 0.0 {
        (size_bytes as f64) / secs / 1e9
    } else {
        0.0
    };
    KernelBenchStats {
        tier,
        backend,
        min_us,
        median_us,
        p95_us,
        mean_us,
        throughput_gbps,
        matches,
    }
}

fn bench_loop<F>(warmup: usize, iters: usize, mut f: F) -> (Vec<f64>, Vec<usize>)
where
    F: FnMut() -> Vec<usize>,
{
    for _ in 0..warmup {
        let res = f();
        black_box(res.len());
    }
    let mut times = Vec::with_capacity(iters);
    let mut last_res = Vec::new();
    for _ in 0..iters {
        let t0 = Instant::now();
        let res = f();
        let dt = (t0.elapsed().as_nanos() as f64) / 1000.0;
        black_box(res.as_ptr());
        black_box(res.len());
        times.push(dt);
        last_res = res;
    }
    (times, last_res)
}

/// Run an honest, reproducible warmup + measured benchmark across Scalar, SIMD, and Fallback tiers.
pub fn run_logforge_benchmark(
    size_bytes: usize,
    warmup: usize,
    iters: usize,
    seed: u64,
    delim: u8,
) -> LogForgeBenchReport {
    let data = generate_synthetic_log_buffer(size_bytes, seed, delim);
    let iters = iters.max(1);

    let (scalar_times, scalar_out) =
        bench_loop(warmup, iters, || scalar::scan_delimiters_scalar(black_box(&data), delim));
    let (simd_times, simd_out) =
        bench_loop(warmup, iters, || scan_delimiters(black_box(&data), delim, false));

    let mut reused_vec = Vec::with_capacity(scalar_out.len() + 16);
    for _ in 0..warmup {
        reused_vec.clear();
        scan_delimiters_into(black_box(&data), delim, false, &mut reused_vec);
        black_box(reused_vec.len());
    }
    let mut reused_times = Vec::with_capacity(iters);
    for _ in 0..iters {
        reused_vec.clear();
        let t0 = Instant::now();
        scan_delimiters_into(black_box(&data), delim, false, &mut reused_vec);
        let dt = (t0.elapsed().as_nanos() as f64) / 1000.0;
        black_box(reused_vec.as_ptr());
        black_box(reused_vec.len());
        reused_times.push(dt);
    }

    let (fb_times, fb_out) =
        bench_loop(warmup, iters, || scan_delimiters(black_box(&data), delim, true));

    let mb_pat = b"||";
    let (mb_scalar_times, mb_scalar_out) = bench_loop(warmup, iters, || {
        scalar::scan_multibyte_delimiters_scalar(black_box(&data), mb_pat)
    });
    let (mb_simd_times, mb_simd_out) = bench_loop(warmup, iters, || {
        scan_multibyte_delimiters(black_box(&data), mb_pat, false)
    });

    let parity_ok = scalar_out == simd_out
        && scalar_out == reused_vec
        && scalar_out == fb_out
        && mb_scalar_out == mb_simd_out;

    let scalar_stats = compute_stats("tier2_rust_scalar", "rust_scalar", scalar_times, size_bytes, scalar_out.len());
    let simd_stats = compute_stats(
        "tier3_rust_simd",
        active_simd_backend(false),
        simd_times,
        size_bytes,
        simd_out.len(),
    );
    let simd_reused_stats = compute_stats(
        "tier3_rust_simd_reused_buf",
        active_simd_backend(false),
        reused_times,
        size_bytes,
        reused_vec.len(),
    );
    let fb_stats = compute_stats(
        "tier3_rust_simd_disabled",
        active_simd_backend(true),
        fb_times,
        size_bytes,
        fb_out.len(),
    );
    let mb_scalar_stats = compute_stats(
        "multibyte_rust_scalar",
        "rust_scalar",
        mb_scalar_times,
        size_bytes,
        mb_scalar_out.len(),
    );
    let mb_simd_stats = compute_stats(
        "multibyte_rust_simd",
        active_simd_backend(false),
        mb_simd_times,
        size_bytes,
        mb_simd_out.len(),
    );

    let speedup = if simd_stats.median_us > 0.0 {
        scalar_stats.median_us / simd_stats.median_us
    } else {
        1.0
    };

    LogForgeBenchReport {
        arch: std::env::consts::ARCH,
        os: std::env::consts::OS,
        size_bytes,
        warmup,
        iters,
        seed,
        delim,
        parity_ok,
        scalar: scalar_stats,
        simd: simd_stats,
        simd_reused_buf: simd_reused_stats,
        simd_fallback: fb_stats,
        multibyte_scalar: mb_scalar_stats,
        multibyte_simd: mb_simd_stats,
        speedup_simd_vs_scalar: speedup,
    }
}

/// Format `LogForgeBenchReport` as deterministic JSON.
pub fn render_bench_report_json(rep: &LogForgeBenchReport) -> String {
    let fmt_stat = |s: &KernelBenchStats| -> String {
        format!(
            "{{\"tier\":\"{}\",\"backend\":\"{}\",\"min_us\":{:.3},\"median_us\":{:.3},\"p95_us\":{:.3},\"mean_us\":{:.3},\"throughput_gbps\":{:.4},\"matches\":{}}}",
            s.tier, s.backend, s.min_us, s.median_us, s.p95_us, s.mean_us, s.throughput_gbps, s.matches
        )
    };
    format!(
        "{{\"schema_version\":\"1.0\",\"tool\":\"LogForge\",\"arch\":\"{}\",\"os\":\"{}\",\"size_bytes\":{},\"warmup\":{},\"iters\":{},\"seed\":{},\"delim\":{},\"parity_ok\":{},\"speedup_simd_vs_scalar\":{:.3},\"results\":{{\"scalar\":{},\"simd\":{},\"simd_reused_buf\":{},\"simd_fallback\":{},\"multibyte_scalar\":{},\"multibyte_simd\":{}}}}}",
        rep.arch,
        rep.os,
        rep.size_bytes,
        rep.warmup,
        rep.iters,
        rep.seed,
        rep.delim,
        rep.parity_ok,
        rep.speedup_simd_vs_scalar,
        fmt_stat(&rep.scalar),
        fmt_stat(&rep.simd),
        fmt_stat(&rep.simd_reused_buf),
        fmt_stat(&rep.simd_fallback),
        fmt_stat(&rep.multibyte_scalar),
        fmt_stat(&rep.multibyte_simd),
    )
}

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
            "plain text line\n"
        )
        .as_bytes();
        let events = normalize_log_records(payload, b'\n', false);
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].format, "jsonl");
        assert_eq!(events[0].timestamp_utc.as_deref(), Some("2026-11-21T11:26:00.5Z"));
        assert_eq!(events[0].level.as_deref(), Some("WARN"));
        assert_eq!(events[1].format, "structured");
        assert_eq!(events[1].level.as_deref(), Some("ERROR"));
        assert_eq!(events[1].message.as_deref(), Some("disk full"));
        assert_eq!(events[2].format, "raw");
        assert_eq!(events[2].raw_preserved, "plain text line");

        let surrogate_payload = b"{\"timestamp\":\"2026-11-21T00:00:00Z\",\"level\":\"info\",\"message\":\"hi \\uD83D\\uDE80!\"}\n";
        let surr_events = normalize_log_records(surrogate_payload, b'\n', false);
        assert_eq!(surr_events.len(), 1);
        assert_eq!(surr_events[0].message.as_deref(), Some("hi 🚀!"));
    }
}
