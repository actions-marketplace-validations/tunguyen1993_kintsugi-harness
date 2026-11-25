//! Deterministic zero-dependency subword token estimator (`kintsugi_core::token_est`).
//! Unconditionally compiled even with `--no-default-features`.
//!
//! Empirically calibrated against `cl100k_base` across a 24-sample multi-domain suite
//! (source code, JSON/SARIF/hook payloads, CLI compact gate lines, and UTF-8 prose) with
//! measured `p50 <= 12%` and `p95 <= 28%` relative error, biased slightly conservative on
//! dense punctuation/UTF-8 so `gate --max-tokens` preserves context headroom.

/// Identifier for the deterministic rule-based subword calibration model (`cl100k_base` p50<=12%, p95<=28%).
pub const HEURISTIC_CALIBRATION_MODEL: &str = "subword_heuristic_v2_cl100k_approx";

#[inline]
fn count_alpha_camel_subwords(seg: &[u8]) -> usize {
    if seg.is_empty() { return 0; }
    let (mut total, mut sub_start) = (0usize, 0usize);
    for k in 1..seg.len() {
        let (prev, curr) = (seg[k - 1], seg[k]);
        let next_lower = seg.get(k + 1).map_or(false, |n| n.is_ascii_lowercase());
        if (prev.is_ascii_lowercase() && curr.is_ascii_uppercase())
            || (prev.is_ascii_uppercase() && curr.is_ascii_uppercase() && next_lower)
        {
            total += (k - sub_start + 9) / 10;
            sub_start = k;
        }
    }
    total + (seg.len() - sub_start + 9) / 10
}

/// Deterministic zero-dependency rule-based subword token heuristic calibrated against
/// `cl100k_base` (`p50 <= 12%`, `p95 <= 28%` on the 24-sample multi-domain benchmark;
/// monotonically non-decreasing (`estimate(a) <= estimate(a + b)`) across ASCII, JSON,
/// operators, and UTF-8).
pub fn estimate_tokens_heuristic(text: &str) -> usize {
    if text.is_empty() { return 0; }
    let bytes = text.as_bytes();
    let (mut tokens, mut i) = (0usize, 0usize);
    while i < bytes.len() {
        let b = bytes[i];
        if !b.is_ascii() {
            let start = i;
            while i < bytes.len() && !bytes[i].is_ascii() {
                i += 1;
            }
            tokens += (i - start + 2) / 3;
        } else if b.is_ascii_whitespace() {
            let (mut spaces, mut newlines) = (0usize, 0usize);
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                match bytes[i] { b'\n' => newlines += 1, b'\t' => spaces += 4, _ => spaces += 1 }
                i += 1;
            }
            tokens += (spaces / 4) + newlines.saturating_sub(1);
        } else if b.is_ascii_alphabetic() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_alphabetic() { i += 1; }
            tokens += count_alpha_camel_subwords(&bytes[start..i]);
        } else if b == b'_' {
            let start = i;
            while i < bytes.len() && bytes[i] == b'_' { i += 1; }
            let joins = (i - start) == 1 && start > 0 && bytes[start - 1].is_ascii_alphanumeric()
                && i < bytes.len() && bytes[i].is_ascii_alphanumeric();
            if !joins { tokens += 1; }
        } else if b.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() { i += 1; }
            tokens += (i - start + 2) / 3;
        } else if [b"..." as &[u8], b"===", b"!==", b"\":\"", b"\",\"", b"\"}}"]
            .iter()
            .any(|op| bytes[i..].starts_with(op))
        {
            tokens += 1;
            i += 3;
        } else if i + 1 < bytes.len() && matches!(
            &bytes[i..i + 2],
            b".." | b"==" | b"!=" | b"<=" | b">=" | b"->" | b"=>" | b"::" | b"&&" | b"||"
                | b"+=" | b"-=" | b"*=" | b"/=" | b"//" | b"/*" | b"*/" | b"\":" | b"\","
                | b"{\"" | b"\"}" | b"()" | b"[]" | b"{}"
        ) {
            tokens += 1;
            i += 2;
        } else {
            tokens += 1;
            i += 1;
        }
    }
    tokens.max(usize::from(!text.trim().is_empty()))
}

/// Estimate subword token count using [`estimate_tokens_heuristic`].
#[inline]
pub fn estimate_tokens(text: &str) -> usize { estimate_tokens_heuristic(text) }

/// Deprecated backward-compatible alias delegating to [`estimate_tokens_heuristic`].
/// Rule-based subword estimator calibrated against `cl100k_base`, NOT a merge-table BPE tokenizer.
#[deprecated(since = "2.4.1", note = "Rule-based subword heuristic, not merge-table BPE; use estimate_tokens_heuristic")]
#[inline]
pub fn estimate_bpe_tokens(text: &str) -> usize { estimate_tokens_heuristic(text) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn empty_punctuation_utf8_and_monotonic_ascii_append() {
        assert_eq!(estimate_tokens_heuristic(""), 0);
        assert_eq!(estimate_bpe_tokens(""), 0);
        assert!(estimate_tokens("{\"ok\":true,\"count\":123456}") >= 10);
        assert!(estimate_tokens("Xin chào 🚀 日本語") > estimate_tokens("Xin"));
        for seed in [
            "camelCase_snake_12345...===!==\":\",///* */",
            "a.b..c...d=e==f===g_h   \t\n\nHTTPSConn",
            "{\"k\":\"v\",\"arr\":[],\"obj\":{}}",
        ] {
            let (mut acc, mut prev) = (String::new(), 0usize);
            for ch in seed.chars() {
                acc.push(ch);
                let cur = estimate_tokens_heuristic(&acc);
                assert!(cur >= prev, "non-monotonic on {acc:?}: {prev} -> {cur}");
                prev = cur;
            }
        }
    }

    const PROP_FRAGMENTS: [&str; 24] = [
        "pub fn scan(input: &str) -> Vec<Finding> {",
        "let x = a..=b; y += 1; z != w && q || r",
        "/* block */ // line comment",
        "HTTPSConnectionPool::new(max_retries)",
        "snake_case_ident_42 __dunder__",
        "import yaml\ncfg = yaml.safe_load(raw)\n",
        "def run(args, shell=False):\n\treturn 0",
        "x === y !== z ... w",
        "{\"ok\":true,\"count\":123456}",
        "{\"k\":\"v\",\"arr\":[],\"obj\":{}}",
        "\"a\",\"b\":\"c\"}}",
        "[KS-020@src/loader.py:14] Replace yaml.load",
        "SELECT id FROM t WHERE s = $1 LIMIT 50;",
        "git -C repo diff -U0 --staged",
        "    \t\n\n   ",
        "9876543210",
        "Kiểm toán bảo mật mã nguồn tự động",
        "Xin chào thế giới",
        "日本語の静的解析エンジン",
        "中文分词测试",
        "🚀🔒✅🦀",
        "Café résumé naïve —",
        "aBcDeFgHiJkLmNoPqRsTuV",
        "=>->::<=>=",
    ];
    const PROP_CHARS: [char; 20] = [
        'a', 'Z', '_', '0', '.', '=', '!', '"', ':', ',', '{', '}', '/', '*', ' ', '\n', '\t', 'ệ', '語', '🚀',
    ];

    fn lcg_next(state: &mut u64) -> usize {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (*state >> 33) as usize
    }

    fn gen_piece(state: &mut u64, out: &mut String) {
        let parts = 1 + lcg_next(state) % 5;
        for _ in 0..parts {
            if lcg_next(state) % 3 == 0 {
                out.push(PROP_CHARS[lcg_next(state) % PROP_CHARS.len()]);
            } else {
                let frag = PROP_FRAGMENTS[lcg_next(state) % PROP_FRAGMENTS.len()];
                let take = lcg_next(state) % (frag.chars().count() + 1);
                out.extend(frag.chars().take(take));
            }
        }
    }

    #[test]
    fn monotonic_non_decreasing_property_500_lcg_pairs() {
        let mut state: u64 = 0x4B49_4E54_5355_4749;
        let mut passed = 0usize;
        for case in 0..500usize {
            let (mut prefix, mut suffix) = (String::new(), String::new());
            gen_piece(&mut state, &mut prefix);
            gen_piece(&mut state, &mut suffix);
            let joined = format!("{prefix}{suffix}");
            let (a, ab) = (estimate_tokens_heuristic(&prefix), estimate_tokens_heuristic(&joined));
            assert!(a <= ab, "case {case}: estimate({prefix:?})={a} > estimate({joined:?})={ab}");
            passed += 1;
        }
        assert_eq!(passed, 500);
    }

    #[test]
    fn calibration_corpus_p50_p95_error_bounds() {
        // 24-sample multi-domain corpus paired with exact precomputed `cl100k_base` token counts:
        // 6 source code + 6 JSON/SARIF/hook + 6 CLI compact/KML wire lines + 6 English/UTF-8 prose.
        const CORPUS: [(&str, usize); 24] = [
            // 1..=6: Source code (Python, Rust, JS, SQL, Shell)
            ("import yaml\ncfg = yaml.safe_load(raw)\n", 10),
            ("subprocess.run(args, shell=False, check=True)", 11),
            ("pub fn scan_text(input: &str, max_tokens: usize) -> Vec<Finding>", 19),
            ("const data = await fetch(url, { signal: AbortSignal.timeout(5000) });", 18),
            ("SELECT user_id, created_at FROM ledger_events WHERE status = $1 LIMIT 50;", 18),
            ("git -C repo diff -U0 --no-color --staged", 13),
            // 7..=12: JSON, PreToolUse hook, RuleIR/1, and SARIF payloads
            ("{\"ok\":true,\"schema_version\":\"2.4.1\",\"findings_count\":0,\"truncated\":false}", 23),
            ("{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"}}", 17),
            ("{\"scar_id\":\"KS-020\",\"severity\":\"HIGH\",\"file_path\":\"src/loader.py\",\"line\":14}", 24),
            ("{\"ok\":false,\"error_code\":\"UNKNOWN_FLAG\",\"error\":\"Unknown option: --bad\"}", 21),
            ("{\"schema\":\"RuleIR/1\",\"rule_id\":\"KS-EVO-910001\",\"revision\":1,\"severity\":\"HIGH\"}", 26),
            ("{\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"kintsugi-rs\"}},\"results\":[]}]}", 27),
            // 13..=18: CLI compact gate lines & @KML/1 wire headers
            ("[KS-020@src/loader.py:14] Replace yaml.load with yaml.safe_load", 18),
            ("[KS-002@scripts/deploy.py:88] Pass argv list with shell=False\n... (+4 more)", 22),
            ("[KS-019@src/auth.py:3] Strip Trojan Source bidirectional Unicode controls", 18),
            ("[KS-S3-SEAM@src/db.rs:1] Prove all seams with canonical S3 parameterization locks", 23),
            ("# KINTSUGI-KMI/1 | @STEP_ECONOMICS/1[rule=R132|shell>=60%|sub<=12|task<=25]", 31),
            ("Kintsugi-RS Native Scan: 42 file(s) checked against 36 scars in 1.250ms", 23),
            // 19..=24: English & multilingual UTF-8 prose
            ("Sub-millisecond Rust native guardrail scanner for autonomous coding agents.", 13),
            ("Every FFI entrypoint validates non-null pointers, alignment, and non-overlapping slices.", 16),
            ("Fail-closed git staged scanning reads index blobs directly without working-tree fallback.", 16),
            ("Kiểm toán bảo mật mã nguồn tự động không cần thư viện ngoài.", 22),
            ("ゼロ依存の高速静的解析エンジンとメモリ安全性検証", 23),
            ("Café résumé naïve — deterministic UTF-8 token budget 🚀🔒", 17),
        ];

        let mut rel_errors: Vec<f64> = Vec::with_capacity(CORPUS.len());
        for (sample, exact_cl100k) in CORPUS {
            let est = estimate_tokens_heuristic(sample);
            let rel_err = (est as f64 - exact_cl100k as f64).abs() / (exact_cl100k as f64);
            // Budget safety: heuristic must never severely undercount real tokens (> 15%).
            assert!(
                (est as f64) >= (exact_cl100k as f64) * 0.85,
                "unsafe token budget undercount on {sample:?}: est={est} vs cl100k={exact_cl100k}"
            );
            rel_errors.push(rel_err);
        }

        rel_errors.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = rel_errors.len();
        assert_eq!(n, 24);
        let p50 = 0.5 * (rel_errors[n / 2 - 1] + rel_errors[n / 2]);
        let p95_idx = ((n as f64) * 0.95).ceil() as usize - 1;
        let p95 = rel_errors[p95_idx];

        assert!(p50 <= 0.12, "p50 relative error {p50:.4} exceeded 12% bound");
        assert!(p95 <= 0.28, "p95 relative error {p95:.4} exceeded 28% bound");
    }
}
