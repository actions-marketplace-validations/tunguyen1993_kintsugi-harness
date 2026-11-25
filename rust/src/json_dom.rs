//! Canonical pure-Rust JSON DOM parser, RFC 8785 (JCS) serializer, and `RuleIR/1` SHA-256 hash verifier.
//!
//! Enforces `MAX_JSON_DEPTH = 64`, `MAX_JSON_NODES = 32_768`, duplicate-key rejection, finite IEEE-754
//! number validation, RFC 8785 §3.2.2.3 number canonicalization, and UTF-16 code-unit key ordering.

use std::collections::BTreeMap;

use crate::policy::sha256_hex;

/// Maximum allowed JSON array/object nesting depth before fail-closed rejection.
pub const MAX_JSON_DEPTH: usize = 64;
/// Maximum allowed JSON DOM nodes to prevent wide/flat JSON memory exhaustion bombs.
pub const MAX_JSON_NODES: usize = 32_768;

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(String),
    Str(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

/// Validate RFC 8259 JSON number syntax and canonicalize per RFC 8785 §3.2.2.3 (ECMA-262 `Number::toString`).
pub fn canonicalize_jcs_number(raw: &str) -> Result<String, String> {
    let bytes = raw.as_bytes();
    if bytes.is_empty() { return Err("Empty JSON number".to_string()); }
    let mut p = usize::from(bytes[0] == b'-');
    match bytes.get(p) {
        Some(b'0') => p += 1,
        Some(b'1'..=b'9') => {
            p += 1;
            while p < bytes.len() && bytes[p].is_ascii_digit() { p += 1; }
        }
        _ => return Err(format!("Invalid JSON number '{raw}'")),
    }
    if bytes.get(p) == Some(&b'.') {
        p += 1;
        if !bytes.get(p).is_some_and(|b| b.is_ascii_digit()) { return Err(format!("Invalid JSON fraction in '{raw}'")); }
        while p < bytes.len() && bytes[p].is_ascii_digit() { p += 1; }
    }
    if matches!(bytes.get(p), Some(b'e' | b'E')) {
        p += 1;
        if matches!(bytes.get(p), Some(b'+' | b'-')) { p += 1; }
        if !bytes.get(p).is_some_and(|b| b.is_ascii_digit()) { return Err(format!("Invalid JSON exponent in '{raw}'")); }
        while p < bytes.len() && bytes[p].is_ascii_digit() { p += 1; }
    }
    if p != bytes.len() { return Err(format!("Trailing characters in JSON number '{raw}'")); }

    let val: f64 = raw.parse().map_err(|_| format!("Unparseable IEEE-754 number '{raw}'"))?;
    if !val.is_finite() { return Err(format!("Non-finite IEEE-754 JSON number '{raw}'")); }
    if val == 0.0 { return Ok("0".to_string()); }

    let sci = format!("{:e}", val.abs());
    let (mant, exp_str) = sci.split_once('e').ok_or_else(|| "Internal float format error".to_string())?;
    let exp: i32 = exp_str.parse().map_err(|_| "Internal exponent parse error".to_string())?;
    let mut digits: String = mant.chars().filter(|&c| c != '.').collect();
    while digits.len() > 1 && digits.ends_with('0') { digits.pop(); }

    let (k, n) = (digits.len() as i32, exp + 1);
    let mut out = String::with_capacity(24);
    if val.is_sign_negative() { out.push('-'); }
    if k <= n && n <= 21 {
        out.push_str(&digits);
        for _ in 0..(n - k) { out.push('0'); }
    } else if 0 < n && n <= 21 {
        let split = n as usize;
        out.push_str(&digits[..split]);
        out.push('.');
        out.push_str(&digits[split..]);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        for _ in 0..(-n) { out.push('0'); }
        out.push_str(&digits);
    } else {
        if k == 1 { out.push_str(&digits); } else { out.push_str(&digits[..1]); out.push('.'); out.push_str(&digits[1..]); }
        out.push('e');
        if n - 1 >= 0 { out.push('+'); }
        out.push_str(&(n - 1).to_string());
    }
    Ok(out)
}

impl JsonValue {
    pub fn as_str(&self) -> Option<&str> { if let JsonValue::Str(s) = self { Some(s.as_str()) } else { None } }
    pub fn as_bool(&self) -> Option<bool> { if let JsonValue::Bool(b) = self { Some(*b) } else { None } }
    pub fn as_object(&self) -> Option<&BTreeMap<String, JsonValue>> { if let JsonValue::Object(m) = self { Some(m) } else { None } }
    pub fn as_array(&self) -> Option<&[JsonValue]> { if let JsonValue::Array(a) = self { Some(a.as_slice()) } else { None } }

    /// Canonical UTF-8 JSON per RFC 8785 (JCS), also matching Python canonical `json.dumps`.
    pub fn to_canonical_json(&self) -> String {
        let mut out = String::new();
        self.write_canonical(&mut out);
        out
    }

    fn write_canonical(&self, out: &mut String) {
        match self {
            JsonValue::Null => out.push_str("null"),
            JsonValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            JsonValue::Number(raw) => match canonicalize_jcs_number(raw) {
                Ok(canon) => out.push_str(&canon),
                Err(_) => out.push_str(raw),
            },
            JsonValue::Str(s) => write_canonical_json_str(s, out),
            JsonValue::Array(arr) => {
                out.push('[');
                for (i, item) in arr.iter().enumerate() {
                    if i > 0 { out.push(','); }
                    item.write_canonical(out);
                }
                out.push(']');
            }
            JsonValue::Object(map) => {
                out.push('{');
                if map.keys().any(|k| !k.is_ascii() && k.chars().any(|c| (c as u32) >= 0xE000)) {
                    let mut pairs: Vec<(&String, &JsonValue)> = map.iter().collect();
                    pairs.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
                    for (i, (k, v)) in pairs.into_iter().enumerate() {
                        if i > 0 { out.push(','); }
                        write_canonical_json_str(k, out);
                        out.push(':');
                        v.write_canonical(out);
                    }
                } else {
                    for (i, (k, v)) in map.iter().enumerate() {
                        if i > 0 { out.push(','); }
                        write_canonical_json_str(k, out);
                        out.push(':');
                        v.write_canonical(out);
                    }
                }
                out.push('}');
            }
        }
    }
}

pub fn write_canonical_json_str(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""), '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"), '\u{000C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"), '\r' => out.push_str("\\r"), '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

pub struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
    nodes: usize,
}

impl<'a> JsonParser<'a> {
    pub fn new(raw: &'a str) -> Self { Self { bytes: raw.as_bytes(), pos: 0, nodes: 0 } }

    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_whitespace() { self.pos += 1; }
    }

    #[inline]
    fn bump_node(&mut self) -> Result<(), String> {
        self.nodes += 1;
        if self.nodes > MAX_JSON_NODES {
            return Err(format!("JSON node count exceeded maximum ({MAX_JSON_NODES})"));
        }
        Ok(())
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, String> {
        if depth > MAX_JSON_DEPTH { return Err(format!("JSON nesting depth exceeded maximum ({MAX_JSON_DEPTH})")); }
        self.bump_node()?;
        self.skip_ws();
        let Some(&b) = self.bytes.get(self.pos) else { return Err("Unexpected end of JSON".to_string()) };
        match b {
            b'{' => self.parse_object(depth + 1),
            b'[' => self.parse_array(depth + 1),
            b'"' => self.parse_string().map(JsonValue::Str),
            b't' if self.bytes[self.pos..].starts_with(b"true") => { self.pos += 4; Ok(JsonValue::Bool(true)) }
            b'f' if self.bytes[self.pos..].starts_with(b"false") => { self.pos += 5; Ok(JsonValue::Bool(false)) }
            b'n' if self.bytes[self.pos..].starts_with(b"null") => { self.pos += 4; Ok(JsonValue::Null) }
            b'-' | b'0'..=b'9' => self.parse_number(),
            other => Err(format!("Unexpected JSON byte '{}'", other as char)),
        }
    }

    fn parse_unicode_escape(&mut self) -> Result<char, String> {
        if self.pos + 4 >= self.bytes.len() { return Err("Incomplete unicode escape".to_string()); }
        let hex = std::str::from_utf8(&self.bytes[self.pos + 1..self.pos + 5]).map_err(|_| "Invalid UTF-8 in unicode escape".to_string())?;
        let code = u16::from_str_radix(hex, 16).map_err(|_| "Invalid hex in unicode escape".to_string())?;
        self.pos += 4;
        if (0xD800..=0xDBFF).contains(&code) {
            if self.pos + 6 >= self.bytes.len() || self.bytes[self.pos + 1] != b'\\' || self.bytes[self.pos + 2] != b'u' {
                return Err("Unpaired high surrogate in JSON string".to_string());
            }
            let lo_hex = std::str::from_utf8(&self.bytes[self.pos + 3..self.pos + 7]).map_err(|_| "Invalid surrogate escape".to_string())?;
            let lo = u16::from_str_radix(lo_hex, 16).map_err(|_| "Invalid surrogate hex".to_string())?;
            if !(0xDC00..=0xDFFF).contains(&lo) { return Err("Unpaired high surrogate in JSON string".to_string()); }
            self.pos += 6;
            let cp = 0x10000 + ((((code as u32) - 0xD800) << 10) | ((lo as u32) - 0xDC00));
            char::from_u32(cp).ok_or_else(|| "Invalid surrogate scalar".to_string())
        } else if (0xDC00..=0xDFFF).contains(&code) {
            Err("Unpaired low surrogate in JSON string".to_string())
        } else {
            char::from_u32(code as u32).ok_or_else(|| "Invalid unicode scalar".to_string())
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        if self.bytes.get(self.pos) != Some(&b'"') { return Err("Expected '\"'".to_string()); }
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            if b == b'"' { self.pos += 1; return Ok(out); }
            if b == b'\\' {
                self.pos += 1;
                let Some(&esc) = self.bytes.get(self.pos) else { return Err("Unterminated escape".to_string()) };
                match esc {
                    b'"' => out.push('"'), b'\\' => out.push('\\'), b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'), b'f' => out.push('\u{000C}'),
                    b'n' => out.push('\n'), b'r' => out.push('\r'), b't' => out.push('\t'),
                    b'u' => out.push(self.parse_unicode_escape()?),
                    other => return Err(format!("Invalid JSON escape '\\{}'", other as char)),
                }
                self.pos += 1;
            } else if b < 0x20 {
                return Err("Unescaped control char in JSON string".to_string());
            } else {
                let s = std::str::from_utf8(&self.bytes[self.pos..]).map_err(|_| "Invalid UTF-8 in JSON string".to_string())?;
                let ch = s.chars().next().ok_or_else(|| "Empty tail".to_string())?;
                out.push(ch);
                self.pos += ch.len_utf8();
            }
        }
        Err("Unterminated JSON string".to_string())
    }

    fn parse_number(&mut self) -> Result<JsonValue, String> {
        let start = self.pos;
        if self.bytes.get(self.pos) == Some(&b'-') { self.pos += 1; }
        match self.bytes.get(self.pos) {
            Some(b'0') => self.pos += 1,
            Some(d) if d.is_ascii_digit() => while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() { self.pos += 1; },
            _ => return Err("Invalid JSON number".to_string()),
        }
        if self.bytes.get(self.pos) == Some(&b'.') {
            self.pos += 1;
            if !self.bytes.get(self.pos).is_some_and(|b| b.is_ascii_digit()) { return Err("Invalid JSON fraction".to_string()); }
            while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() { self.pos += 1; }
        }
        if matches!(self.bytes.get(self.pos), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.bytes.get(self.pos), Some(b'+' | b'-')) { self.pos += 1; }
            if !self.bytes.get(self.pos).is_some_and(|b| b.is_ascii_digit()) { return Err("Invalid JSON exponent".to_string()); }
            while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() { self.pos += 1; }
        }
        let lex = std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|_| "Invalid UTF-8 in number".to_string())?;
        canonicalize_jcs_number(lex).map(JsonValue::Number)
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonValue, String> {
        if depth > MAX_JSON_DEPTH { return Err(format!("JSON nesting depth exceeded maximum ({MAX_JSON_DEPTH})")); }
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.bytes.get(self.pos) == Some(&b']') { self.pos += 1; return Ok(JsonValue::Array(items)); }
        loop {
            items.push(self.parse_value(depth)?);
            self.skip_ws();
            match self.bytes.get(self.pos) {
                Some(&b',') => self.pos += 1,
                Some(&b']') => { self.pos += 1; return Ok(JsonValue::Array(items)); }
                _ => return Err("Expected ',' or ']' in JSON array".to_string()),
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonValue, String> {
        if depth > MAX_JSON_DEPTH { return Err(format!("JSON nesting depth exceeded maximum ({MAX_JSON_DEPTH})")); }
        self.pos += 1;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.bytes.get(self.pos) == Some(&b'}') { self.pos += 1; return Ok(JsonValue::Object(map)); }
        loop {
            self.skip_ws();
            let key_byte = self.pos;
            let key = self.parse_string()?;
            if map.contains_key(&key) {
                return Err(format!("Duplicate JSON object key '{key}' at byte {key_byte}"));
            }
            self.skip_ws();
            if self.bytes.get(self.pos) != Some(&b':') { return Err("Expected ':' in JSON object".to_string()); }
            self.pos += 1;
            map.insert(key, self.parse_value(depth)?);
            self.skip_ws();
            match self.bytes.get(self.pos) {
                Some(&b',') => self.pos += 1,
                Some(&b'}') => { self.pos += 1; return Ok(JsonValue::Object(map)); }
                _ => return Err("Expected ',' or '}' in JSON object".to_string()),
            }
        }
    }
}

pub fn parse_json_value(raw: &str) -> Result<JsonValue, String> {
    let mut parser = JsonParser::new(raw);
    let val = parser.parse_value(0)?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() { return Err("Trailing characters after JSON value".to_string()); }
    Ok(val)
}

fn clone_opt_obj(obj: &BTreeMap<String, JsonValue>, key: &str) -> Result<BTreeMap<String, JsonValue>, String> {
    match obj.get(key) {
        Some(JsonValue::Object(m)) => Ok(m.clone()),
        Some(JsonValue::Null) | None => Ok(BTreeMap::new()),
        Some(_) => Err(format!("RuleIR {key} must be a JSON object")),
    }
}

/// Compute canonical `RuleIR/1` SHA-256 (`sha256:...`) matching Python `RuleIR.compute_rule_hash()`.
pub fn compute_rule_ir_canonical_hash(obj: &BTreeMap<String, JsonValue>) -> Result<String, String> {
    let mut langs: Vec<String> = match obj.get("language").or_else(|| obj.get("languages")) {
        Some(JsonValue::Array(arr)) if !arr.is_empty() => arr
            .iter()
            .map(|v| v.as_str().map(str::to_string).ok_or_else(|| "RuleIR language entries must be strings".to_string()))
            .collect::<Result<Vec<_>, _>>()?,
        Some(JsonValue::Null) | Some(JsonValue::Array(_)) | None => vec!["python".to_string()],
        Some(_) => return Err("RuleIR language must be a JSON array".to_string()),
    };
    langs.sort();

    let severity = match obj.get("severity") {
        Some(JsonValue::Str(s)) => s.clone(),
        Some(JsonValue::Null) | None => "HIGH".to_string(),
        Some(_) => return Err("RuleIR severity must be a string".to_string()),
    };
    let predicate_kind = obj
        .get("predicate_kind")
        .or_else(|| obj.get("predicate"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Missing RuleIR predicate_kind".to_string())?
        .to_string();

    let mut core = BTreeMap::new();
    core.insert("conditions".to_string(), JsonValue::Object(clone_opt_obj(obj, "conditions")?));
    core.insert("language".to_string(), JsonValue::Array(langs.into_iter().map(JsonValue::Str).collect()));
    core.insert("match".to_string(), JsonValue::Object(clone_opt_obj(obj, "match")?));
    core.insert("predicate_kind".to_string(), JsonValue::Str(predicate_kind));
    core.insert("response".to_string(), JsonValue::Object(clone_opt_obj(obj, "response")?));
    core.insert("severity".to_string(), JsonValue::Str(severity));

    let payload = JsonValue::Object(core).to_canonical_json();
    Ok(format!("sha256:{}", sha256_hex(payload.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc8785_jcs_numbers_duplicate_keys_node_cap_and_utf16_key_sort() {
        for (raw, expected) in [
            ("-0", "0"), ("-0.0", "0"), ("0.000", "0"), ("1.0", "1"), ("1e2", "100"),
            ("9007199254740991", "9007199254740991"), ("1e20", "100000000000000000000"),
            ("1e21", "1e+21"), ("1e-6", "0.000001"), ("1e-7", "1e-7"),
            ("333333333.33333329", "333333333.3333333"),
        ] {
            assert_eq!(parse_json_value(raw).unwrap().to_canonical_json(), expected, "failed on {raw}");
        }
        assert!(parse_json_value("1e400").is_err() && parse_json_value("01").is_err());
        assert!(parse_json_value("{\"alpha\":1,\"alpha\":2}").unwrap_err().contains("Duplicate JSON object key 'alpha'"));
        let wide = format!("[{}]", vec!["0"; MAX_JSON_NODES + 2].join(","));
        assert!(parse_json_value(&wide).unwrap_err().contains("JSON node count exceeded"));
        assert_eq!(parse_json_value("{\"\\ue000\":1,\"\\ud83d\\ude00\":2}").unwrap().to_canonical_json(), "{\"😀\":2,\"\u{e000}\":1}");
    }
}
