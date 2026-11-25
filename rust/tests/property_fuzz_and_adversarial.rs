// kintsugi: ignore-file
//! Deterministic `XorShift64` Property, Differential & Adversarial Fuzz Suite (1,200+ cases).
//!
//! 1. `300` JSON DOM & `PreToolUse` mutations (malformed deny, benign escaped-key allow, deep nesting).
//! 2. `250` `RulePrefilter` differential cases (`1..=96` rules, `None`/`Small`/`Full` digrams, UTF-8/SIMD).
//! 3. `200` `BoundedRegex` adversarial cases (`>64` nesting, ReDoS `(a+)+b` fail-closed `Err`, random syntax).
//! 4. `200` `parse_git_diff_lines` confinement cases (`b//etc/passwd`, `..`, C-quoted octal, `usize::MAX` hunks).
//! 5. `250` C-ABI FFI boundary + Python alias/whitespace/multiline/PI/`KC-C03` semantic mutations.
#![cfg(all(feature = "audit", feature = "rule-ir", feature = "logforge"))]

use std::mem::size_of;
use std::path::{Component, Path};
use std::ptr;

use kintsugi_core::ffi::{
    kintsugi_abi_compiled_features_v1, kintsugi_abi_features_v1, kintsugi_abi_version,
    kintsugi_rule_ir_eval_v1, kintsugi_scan_buffer_v1, kintsugi_sha256_v1, FEAT_SHA256,
    KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL, KINTSUGI_FFI_ERR_INVALID_ARG,
    KINTSUGI_FFI_ERR_INVALID_UTF8, KINTSUGI_FFI_ERR_NULL_PTR, KINTSUGI_FFI_ERR_OVERFLOW,
    KINTSUGI_FFI_ERR_RULE_INVALID, KINTSUGI_FFI_OK, KINTSUGI_MAX_FFI_INPUT_BYTES,
    KINTSUGI_MAX_FFI_LANG_BYTES, KINTSUGI_MAX_FFI_RULE_BYTES,
};
use kintsugi_core::kernels::{LiteralSpec, RulePrefilter};
use kintsugi_core::{
    evaluate_pre_tool_json, evaluate_rule_ir_json_no_fs, json_escape, parse_git_diff_lines,
    parse_json_value, scan_arm_c_shadow_text, scan_text, sha256_hex, BoundedRegex, JsonObj,
    Severity, MAX_DIFF_HUNK_LINES, MAX_JSON_DEPTH, MAX_REGEX_RECURSION_DEPTH,
};

#[derive(Clone, Copy)]
struct XorShift64(u64);

impl XorShift64 {
    const fn new(seed: u64) -> Self {
        Self(if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed })
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    #[inline]
    fn range(&mut self, lo: usize, hi_inclusive: usize) -> usize {
        if lo >= hi_inclusive { lo } else { lo + (self.next_u64() as usize) % (hi_inclusive - lo + 1) }
    }

    #[inline]
    fn coin(&mut self) -> bool {
        (self.next_u64() & 1) != 0
    }

    fn ascii_word(&mut self, min_len: usize, max_len: usize) -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:/-=";
        let len = self.range(min_len, max_len);
        (0..len).map(|_| ALPHABET[self.range(0, ALPHABET.len() - 1)] as char).collect()
    }

    fn mixed_utf8_haystack(&mut self, len_hint: usize) -> Vec<u8> {
        const TOKENS: &[&str] = &[
            "alpha", "beta", "SELECT", "from", "yaml", " — ", " → ", " … ",
            "日本語", "việt", "λ", "🚀", "0x7f", "\n", " == ", "(x)",
        ];
        let mut out = String::with_capacity(len_hint + 16);
        while out.len() < len_hint {
            if self.range(0, 3) == 0 {
                out.push_str(TOKENS[self.range(0, TOKENS.len() - 1)]);
            } else {
                out.push(self.range(32, 126) as u8 as char);
            }
        }
        let mut bytes = out.into_bytes();
        if bytes.len() > len_hint {
            let mut cut = len_hint;
            while cut > 0 && std::str::from_utf8(&bytes[..cut]).is_err() {
                cut -= 1;
            }
            bytes.truncate(cut);
        }
        bytes
    }
}

#[test]
fn fuzz_300_json_dom_and_pretool_adversarial_mutations() {
    let mut rng = XorShift64::new(0x2026_1123_A11CE001);
    let mut executed = 0usize;

    // 1a. 100 Benign Write payloads containing escaped `"tool_input": []`, `"cwd": "/etc"`, Unicode, & clean code
    for idx in 0..100 {
        let ident = format!("calc_metric_{idx}_{}", rng.range(10, 999));
        let prose = match idx % 4 {
            0 => format!("# Spec {idx} — Schema → `{{\"tool_input\": [], \"cwd\": \"/etc\"}}`\ndef {ident}(a: int, b: int) -> int:\n    return a + b\n"),
            1 => format!("Example JSON: {{\"toolCall\": [1, 2], \"workspace_root\": \"/root\", \"note\": \"ok — {ident}\"}}\n"),
            2 => format!("Báo cáo kiểm thử #{idx} … mẫu `{{\"tool_input\": []}}` và `{{\"cwd\": \"/var/lib\"}}` hợp lệ.\n"),
            _ => format!("def {ident}(items: list[int]) -> int:\n    \"\"\"Doc with \"tool_input\": [] and \"cwd\": \"/etc/passwd\".\"\"\"\n    return sum(items)\n"),
        };
        let ti = JsonObj::with_capacity(256).str("file_path", &format!("docs/guide_{idx}.py")).str("content", &prose).finish();
        let payload = JsonObj::with_capacity(320).str("tool_name", "Write").raw("tool_input", &ti).finish();
        let dec = evaluate_pre_tool_json(&payload, Severity::High);
        assert!(dec.contains("\"permissionDecision\":\"allow\""), "Benign case #{idx} denied: {dec}");
        executed += 1;
    }

    // 1b. 100 Malformed JSON, non-object `tool_input`, untrusted `cwd`, & ignore-bypass payloads -> ALWAYS deny!
    for idx in 0..100 {
        let tok = rng.ascii_word(3, 12);
        let adversarial = match idx % 10 {
            0 => format!("{{\"tool_name\":\"Bash\",\"tool_input\":{{\"command\":\"echo {tok}\",}}}}"),
            1 => format!("{{\"tool_name\":\"Write\",\"tool_input\":{{\"content\":\"unclosed_{tok}"),
            2 => format!("{{\"tool_name\":\"Bash\",\"tool_input\":[{idx}, \"{tok}\"]}}"),
            3 => format!("{{\"tool_name\":\"Bash\",\"toolCall\":\"{tok}\"}}"),
            4 => format!("[\"array_root\", {idx}, \"{tok}\"]"),
            5 => format!("{{\"tool_name\":\"Bash\",\"tool_input\":{{\"command\":\"echo\x07{tok}\"}}}}"),
            6 => String::from("{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"rm -rf ./build\",\"cwd\":\"/etc\"}}"),
            7 => format!("{{\"tool_name\":\"Write\",\"tool_input\":{{\"file_path\":\"a.py\",\"content\":\"# kintsugi: ignore-file\\n{tok}\\n\"}}}}"),
            8 => {
                let d = MAX_JSON_DEPTH + 4;
                format!("{}\"leaf\"{}", "{\"a\":".repeat(d), "}".repeat(d))
            }
            _ => format!("{{\"tool_name\":\"Bash\",\"tool_input\":{{\"command\":\"echo {tok}\"\"extra\"}}}}"),
        };
        if matches!(idx % 10, 0 | 1 | 5 | 8 | 9) {
            assert!(parse_json_value(&adversarial).is_err());
        }
        let dec = evaluate_pre_tool_json(&adversarial, Severity::High);
        assert!(dec.contains("\"permissionDecision\":\"deny\""), "Adversarial #{idx} failed open: {dec}");
        executed += 1;
    }

    // 1c. 100 Seeded random byte/bracket/escape fuzz strings -> 0 panics, corrupt inputs always deny!
    const FUZZ_TOK: &[&str] = &[
        "{", "}", "[", "]", ":", ",", "\"", "\\\"", "\\u0000", "\\uD800", "\\n",
        "true", "false", "null", "-0.5e2", "\"tool_input\"", "\"cwd\"", "\"/etc\"", "999999999999999999999",
    ];
    for _ in 0..100 {
        let mut s = String::from("{");
        for _ in 0..rng.range(2, 28) {
            s.push_str(FUZZ_TOK[rng.range(0, FUZZ_TOK.len() - 1)]);
        }
        let parsed = parse_json_value(&s);
        let dec = evaluate_pre_tool_json(&s, Severity::High);
        assert!(dec.contains("\"hookEventName\":\"PreToolUse\""));
        if parsed.is_err() {
            assert!(dec.contains("\"permissionDecision\":\"deny\""));
        }
        executed += 1;
    }
    assert_eq!(executed, 300);
}

/// Differential fuzz across `DigramMode::{None, Small, Full}`, `[u64; 4]` stack (`<= 256`) and heap (`> 256`)
/// bitsets up to 300 rules. Note: `RulePrefilter::verify_trigram_at` performs full slice verification on every
/// Stage-2 CSR hit, so `candidate_rule_indices` achieves exact equality with `scalar_oracle_rule_indices` in addition
/// to upholding the conservative zero-false-negative superset contract (`oracle ⊆ candidates`).
#[test]
fn differential_fuzz_250_rule_prefilter_modes_up_to_300_rules() {
    let mut rng = XorShift64::new(0x2026_1123_BEEF_CAFE);
    const BOUNDARY_LENS: &[usize] = &[0, 1, 2, 3, 7, 15, 16, 17, 18, 31, 32, 33, 47, 48, 49, 63, 64, 65, 127, 192, 320];
    let (mut scratch, mut into_simd, mut into_scalar) = (Vec::new(), Vec::new(), Vec::new());

    for case_idx in 0..250 {
        let num_rules = match case_idx % 5 {
            0 => rng.range(1, 64),
            1 => rng.range(65, 128),
            2 => rng.range(129, 256),
            3 => rng.range(257, 300),
            _ => rng.range(1, 300),
        };
        let digram_target = match case_idx % 3 {
            0 => 0,
            1 => rng.range(1, 16),
            _ => rng.range(17, 40),
        };
        let (single_target, trigram_target) = (rng.range(0, 6), rng.range(0, 42));
        let mut specs = Vec::with_capacity(single_target + digram_target + trigram_target);

        for _ in 0..single_target {
            let pat = if rng.coin() { vec![rng.range(0, 255) as u8] } else { rng.ascii_word(1, 1).into_bytes() };
            specs.push(LiteralSpec { rule_index: rng.range(0, num_rules - 1), pattern: pat, case_insensitive: rng.coin() });
        }
        for _ in 0..digram_target {
            let pat = if rng.coin() { vec![rng.range(0, 255) as u8, rng.range(0, 255) as u8] } else { rng.ascii_word(2, 2).into_bytes() };
            specs.push(LiteralSpec { rule_index: rng.range(0, num_rules - 1), pattern: pat, case_insensitive: rng.coin() });
        }
        for _ in 0..trigram_target {
            let plen = rng.range(3, 14);
            let pat = if rng.coin() {
                (0..plen).map(|_| rng.range(0, 255) as u8).collect::<Vec<u8>>()
            } else {
                rng.ascii_word(plen, plen).into_bytes()
            };
            specs.push(LiteralSpec { rule_index: rng.range(0, num_rules - 1), pattern: pat, case_insensitive: rng.coin() });
        }

        if !specs.is_empty() && rng.coin() {
            let dup_idx = rng.range(0, specs.len() - 1);
            let mut dup = specs[dup_idx].clone();
            dup.rule_index = rng.range(0, num_rules - 1);
            specs.push(dup);
        }

        if trigram_target > 1 && rng.coin() {
            let base_prefix = [rng.range(0, 255) as u8, rng.range(0, 255) as u8, rng.range(0, 255) as u8];
            for _ in 0..rng.range(2, 5) {
                let mut collide = base_prefix.to_vec();
                collide.extend((0..rng.range(0, 8)).map(|_| rng.range(0, 255) as u8));
                specs.push(LiteralSpec { rule_index: rng.range(0, num_rules - 1), pattern: collide, case_insensitive: false });
            }
        }

        let always: Vec<usize> = (0..rng.range(0, 3)).map(|_| rng.range(0, num_rules - 1)).collect();
        let pf = RulePrefilter::new(num_rules, &specs, &always);
        let target_len = BOUNDARY_LENS[case_idx % BOUNDARY_LENS.len()];
        let mut haystack = rng.mixed_utf8_haystack(target_len);

        if !specs.is_empty() && target_len >= 2 {
            for _ in 0..rng.range(0, 4) {
                let sp = &specs[rng.range(0, specs.len() - 1)];
                let mut injected = sp.pattern.clone();
                if sp.case_insensitive && rng.coin() {
                    for b in &mut injected {
                        if b.is_ascii_lowercase() { *b = b.to_ascii_uppercase(); }
                        else if b.is_ascii_uppercase() { *b = b.to_ascii_lowercase(); }
                    }
                }
                let pos = rng.range(0, haystack.len());
                haystack.splice(pos..pos, injected);
            }
        }

        let oracle = pf.scalar_oracle_rule_indices(&haystack);
        let simd_vec = pf.candidate_rule_indices(&haystack, false);
        let scalar_vec = pf.candidate_rule_indices(&haystack, true);
        pf.candidate_rule_indices_into(&haystack, false, &mut scratch, &mut into_simd);
        pf.candidate_rule_indices_into(&haystack, true, &mut scratch, &mut into_scalar);

        assert_eq!(simd_vec, into_simd);
        assert_eq!(scalar_vec, into_scalar);
        assert_eq!(simd_vec, scalar_vec, "case #{case_idx}: SIMD vs scalar backend parity mismatch");
        for &expected_idx in &oracle {
            assert!(simd_vec.binary_search(&expected_idx).is_ok(), "FN SIMD case #{case_idx} rule {expected_idx}");
            assert!(scalar_vec.binary_search(&expected_idx).is_ok(), "FN scalar case #{case_idx} rule {expected_idx}");
        }
    }
}

#[test]
fn adversarial_fuzz_200_bounded_regex_fail_closed_and_no_panic() {
    let mut rng = XorShift64::new(0x2026_1123_D00D_F00D);
    let mut total = 0usize;

    for i in 0..30 {
        let depth = MAX_REGEX_RECURSION_DEPTH + 1 + (i % 25);
        let opener = ["(", "(?:", "(?="][i % 3];
        let pat = format!("{}x{}", opener.repeat(depth), ")".repeat(depth));
        assert!(BoundedRegex::compile(&pat).is_err(), "Depth {depth} must be rejected");
        total += 1;
    }

    for i in 0..20 {
        let pat = if i % 2 == 0 { "a".repeat(351 + i * 5) } else { format!("abc[z-a]{i}") };
        assert!(BoundedRegex::compile(&pat).is_err());
        total += 1;
    }

    const REDOS_PATS: &[&str] = &["(a+)+b", "([a-z]+)+!", "(a|aa)+b", "((a+)+)+z", "(a+a+)+c"];
    for i in 0..50 {
        let rx = BoundedRegex::compile(REDOS_PATS[i % REDOS_PATS.len()]).expect("valid ReDoS pattern");
        let hay = "a".repeat(40 + (i % 15)) + "X";
        if i < 12 {
            assert!(rx.try_find_all(&hay).is_err(), "try_find_all must return Err on ReDoS #{i}");
        } else {
            let mut tight_budget = 15_000usize;
            assert!(rx.find_all_with_budget(&hay, &mut tight_budget).is_err(), "budget must return Err on ReDoS #{i}");
        }
        total += 1;
    }

    let core = "{\"conditions\":{},\"language\":[\"python\"],\"match\":{\"regex\":\"ab(a+)+b\"},\"predicate_kind\":\"bounded_regex\",\"response\":{\"decision\":\"DENY\",\"reason_code\":\"REDOS_TEST\"},\"severity\":\"HIGH\"}";
    let ir_json = format!(
        "{{\"schema\":\"RuleIR/1\",\"rule_id\":\"KS-EVO-999001\",\"language\":[\"python\"],\"severity\":\"HIGH\",\"predicate_kind\":\"bounded_regex\",\"match\":{{\"regex\":\"ab(a+)+b\"}},\"conditions\":{{}},\"response\":{{\"decision\":\"DENY\",\"reason_code\":\"REDOS_TEST\"}},\"rule_hash\":\"sha256:{}\"}}",
        sha256_hex(core.as_bytes())
    );
    if let Ok(ir_out) = evaluate_rule_ir_json_no_fs(&ir_json, &format!("ab{}c\n", "a".repeat(180)), "python") {
        assert!(ir_out.contains("\"decision\":\"DENY\""));
    }

    const RX_ATOMS: &[&str] = &[
        "a", "b", ".", "\\w", "\\d", "\\s", "\\b", "^", "$", "[a-f0-9]", "[^x]",
        "*", "+", "?", "{1,3}", "{2,}", "|", "(ab)", "(?:cd)", "(?=x)", "(?!y)", "[", "(", "\\",
    ];
    for _ in 0..100 {
        let pat: String = (0..rng.range(1, 18)).map(|_| RX_ATOMS[rng.range(0, RX_ATOMS.len() - 1)]).collect();
        if let Ok(rx) = BoundedRegex::compile(&pat) {
            let _ = rx.required_anchor_literals();
            let len = rng.range(0, 96);
            let hay_bytes = rng.mixed_utf8_haystack(len);
            let mut budget = 10_000usize;
            let _ = rx.find_all_with_budget(&String::from_utf8_lossy(&hay_bytes), &mut budget);
        }
        total += 1;
    }
    assert_eq!(total, 200);
}

#[test]
fn adversarial_fuzz_200_git_diff_confinement_and_hunk_bounds() {
    let mut rng = XorShift64::new(0x2026_1123_617D_1FF5);
    let repo_root = Path::new("/srv/kintsugi_repo");
    const ADV_HEADERS: &[&str] = &[
        "+++ b//etc/passwd", "+++ /etc/shadow", "+++ b///root/.ssh/authorized_keys",
        "+++ b/sub/../../secret.py", "+++ b/../escape.py", "+++ b/a/b/c/../../../../etc/hosts",
        "+++ \"b/..\\\\..\\\\secret.py\"", "+++ \"b//etc/passwd\"", "+++ \"b/\\056\\056/secret.py\"",
        "+++ \"b/\\\\056\\\\056/inside_octal_literal.py\"", "+++ b/src/clean_.._module.py",
        "+++ \"b/src/quoted_\\\"ok\\\".py\"", "+++ /dev/null", "+++ missing_b_prefix/file.py", "+++ b/", "+++ b/.",
    ];
    const ADV_HUNKS: &[&str] = &[
        "@@ -0,0 +0,0 @@", "@@ -1,1 +0,5 @@", "@@ -1,1 +18446744073709551615,18446744073709551615 @@",
        "@@ -1,1 +18446744073709551610,999999999 @@", "@@ -1,1 +10,250000 @@",
        "@@ -1 +1,-9 @@", "@@ malformed hunk @@", "@@ -5,2 +42 @@",
    ];

    for idx in 0..200 {
        let mut diff = String::new();
        if idx % 3 != 0 {
            diff.push_str("--- a/spoofed_origin.py\n");
        }
        if idx % 13 == 0 {
            diff.push_str("+++ b/src/nul\0injected.py\n@@ -1,1 +1,4 @@\n");
        }
        let rand_start = if idx % 7 == 0 { usize::MAX } else { rng.range(0, 500) };
        let rand_cnt = if idx % 11 == 0 { usize::MAX } else { rng.range(0, 64) };
        diff.push_str(&format!(
            "{}\n{}\n+++ b/pkg_{}/{}.py\n@@ -1,1 +{rand_start},{rand_cnt} @@\n",
            ADV_HEADERS[idx % ADV_HEADERS.len()],
            ADV_HUNKS[idx % ADV_HUNKS.len()],
            rng.range(0, 9),
            rng.ascii_word(2, 10)
        ));

        let parsed = parse_git_diff_lines(&diff, repo_root);
        for (path, lines) in &parsed {
            assert!(path.starts_with(repo_root), "Case #{idx} escaped: {}", path.display());
            assert!(!path.components().any(|c| matches!(c, Component::ParentDir)));
            assert!(lines.len() <= MAX_DIFF_HUNK_LINES + 64);
        }
    }
}

#[test]
fn adversarial_fuzz_250_ffi_abi_and_alias_multiline_mutations() {
    let mut rng = XorShift64::new(0x2026_1123_FF10_AB10);
    assert_eq!(kintsugi_abi_version(), 1);
    let (comp, rt) = (kintsugi_abi_compiled_features_v1(), kintsugi_abi_features_v1());
    assert_eq!(rt & comp, comp);
    assert_ne!(comp & FEAT_SHA256, 0);

    let (mut ffi_cases, mut shared, mut out_buf, mut out_len) = (0usize, [b'x'; 256], vec![0u8; 4096], 0usize);

    // 5a. 125 FFI boundary cases (null, out_cap 0..=65, overlap, invalid UTF-8, 16MiB+1 overflow, probe)
    for cap in 0..=65usize {
        // SAFETY: the input is a 3-byte static literal. The output is `shared` (256 bytes), and
        // `cap` is at most 65, which is <= 256, so every write stays in bounds. The two buffers
        // do not overlap.
        let rc = unsafe { kintsugi_sha256_v1(b"abc".as_ptr(), 3, shared.as_mut_ptr(), cap) };
        if cap < 64 {
            assert_eq!(rc, KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL);
        } else {
            assert_eq!(rc, KINTSUGI_FFI_OK);
            assert_eq!(&shared[..64], b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        }
        ffi_cases += 1;
    }

    const BAD_UTF8_SAMPLES: &[&[u8]] = &[&[0x80], &[0xC0, 0xAF], &[0xED, 0xA0, 0x80], &[0xF0, 0x9F, 0x9A], &[0xFF, 0xFE, 0xFD]];
    for idx in 0..59usize {
        match idx % 6 {
            0 => {
                let off = idx % 32;
                // SAFETY: `off` < 32, so `off + 32` <= 64 and `off / 2 + 64` <= 80, both inside the
                // 256-byte `shared` buffer. The overlap is intentional and is rejected before any
                // dereference.
                let rc = unsafe { kintsugi_scan_buffer_v1(shared.as_ptr().add(off), 32, b"python".as_ptr(), 6, shared.as_mut_ptr().add(off / 2), 64, &mut out_len) };
                assert_eq!(rc, KINTSUGI_FFI_ERR_INVALID_ARG);
            }
            1 => {
                let mut word = 0usize;
                // SAFETY: the input is a 4-byte static literal. The output aliases the live `word`
                // (size_of::<usize>() bytes, its true size) on purpose, so the FFI must return
                // INVALID_ARG for the out_len/out_buf alias before writing.
                let rc = unsafe { kintsugi_scan_buffer_v1(b"x=1\n".as_ptr(), 4, b"python".as_ptr(), 6, (&mut word as *mut usize) as *mut u8, size_of::<usize>(), &mut word) };
                assert_eq!(rc, KINTSUGI_FFI_ERR_INVALID_ARG);
            }
            2 => {
                let bad = BAD_UTF8_SAMPLES[idx % BAD_UTF8_SAMPLES.len()];
                // SAFETY: every pointer/length pair describes a live slice or Vec (`bad`, the static
                // lang literal, `out_buf`). `out_len` is a valid, non-aliased `&mut usize`.
                let rc = unsafe { kintsugi_scan_buffer_v1(bad.as_ptr(), bad.len(), b"python".as_ptr(), 6, out_buf.as_mut_ptr(), out_buf.len(), &mut out_len) };
                assert_eq!(rc, KINTSUGI_FFI_ERR_INVALID_UTF8);
            }
            3 => {
                let over_in = if idx % 2 == 0 { KINTSUGI_MAX_FFI_INPUT_BYTES + 1 } else { usize::MAX };
                // SAFETY: each over-sized length goes past its real buffer on purpose. The FFI
                // contract rejects any length above its KINTSUGI_MAX_FFI_* cap with OVERFLOW before
                // it touches the pointer. All output pointers are live and correctly sized.
                let (rc_in, rc_lang, rc_rule) = unsafe {
                    (
                        kintsugi_scan_buffer_v1(b"x".as_ptr(), over_in, b"python".as_ptr(), 6, out_buf.as_mut_ptr(), out_buf.len(), &mut out_len),
                        kintsugi_scan_buffer_v1(b"x".as_ptr(), 1, b"python".as_ptr(), KINTSUGI_MAX_FFI_LANG_BYTES + 1, out_buf.as_mut_ptr(), out_buf.len(), &mut out_len),
                        kintsugi_rule_ir_eval_v1(b"{}".as_ptr(), KINTSUGI_MAX_FFI_RULE_BYTES + 1, b"x".as_ptr(), 1, b"python".as_ptr(), 6, out_buf.as_mut_ptr(), out_buf.len(), &mut out_len),
                    )
                };
                assert_eq!(rc_in, KINTSUGI_FFI_ERR_OVERFLOW);
                assert_eq!(rc_lang, KINTSUGI_FFI_ERR_OVERFLOW);
                assert_eq!(rc_rule, KINTSUGI_FFI_ERR_OVERFLOW);
            }
            4 => {
                // SAFETY: the null input is intentional and is rejected with NULL_PTR before any
                // dereference. All other pointers are live static literals or `out_buf` with its
                // true length.
                let (rc_null, rc_rule) = unsafe {
                    (
                        kintsugi_scan_buffer_v1(ptr::null(), 4, b"python".as_ptr(), 6, out_buf.as_mut_ptr(), out_buf.len(), &mut out_len),
                        kintsugi_rule_ir_eval_v1(b"{\"bad\":1}".as_ptr(), 9, b"x=1".as_ptr(), 3, b"python".as_ptr(), 6, out_buf.as_mut_ptr(), out_buf.len(), &mut out_len),
                    )
                };
                assert_eq!(rc_null, KINTSUGI_FFI_ERR_NULL_PTR);
                assert_eq!(rc_rule, KINTSUGI_FFI_ERR_RULE_INVALID);
            }
            _ => {
                let snippet = format!("val_{idx} = {}\n", rng.range(1, 9999));
                let mut needed = 0usize;
                // SAFETY: `snippet` is a live String. The null lang with length 0 and the null
                // output with cap 0 are valid size-probe arguments under the FFI contract.
                let rc_probe = unsafe { kintsugi_scan_buffer_v1(snippet.as_ptr(), snippet.len(), ptr::null(), 0, ptr::null_mut(), 0, &mut needed) };
                assert_eq!(rc_probe, KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL);
                let mut short = vec![0u8; needed.saturating_sub(1)];
                // SAFETY: `short` is a live Vec, and its pointer/len pair is exact.
                let rc_short = unsafe { kintsugi_scan_buffer_v1(snippet.as_ptr(), snippet.len(), ptr::null(), 0, short.as_mut_ptr(), short.len(), &mut needed) };
                assert_eq!(rc_short, KINTSUGI_FFI_ERR_BUFFER_TOO_SMALL);
                let mut exact = vec![0u8; needed];
                // SAFETY: `exact` is a live Vec, and its pointer/len pair is exact.
                let rc_exact = unsafe { kintsugi_scan_buffer_v1(snippet.as_ptr(), snippet.len(), ptr::null(), 0, exact.as_mut_ptr(), exact.len(), &mut needed) };
                assert_eq!(rc_exact, KINTSUGI_FFI_OK);
                let mut with_nul = vec![0xFFu8; needed + 1];
                // SAFETY: `with_nul` is a live Vec, and its pointer/len pair is exact.
                let rc_nul = unsafe { kintsugi_scan_buffer_v1(snippet.as_ptr(), snippet.len(), ptr::null(), 0, with_nul.as_mut_ptr(), with_nul.len(), &mut needed) };
                assert_eq!(rc_nul, KINTSUGI_FFI_OK);
                assert_eq!(with_nul[needed], 0);
            }
        }
        ffi_cases += 1;
    }
    assert_eq!(ffi_cases, 125);

    // 5b. 125 Alias, whitespace, multiline, benign PI substring, & KC-C03 HMAC false-positive cases
    const ALIASES: &[&str] = &["ym", "y_cfg", "mod_ref", "pkg_a", "h_alias", "runner_fn", "th", "pt_mod"];
    let mut sem_cases = 0usize;
    for i in 0..25usize {
        let (al, sp) = (ALIASES[i % ALIASES.len()], " ".repeat((i % 3) + 1));

        let yaml_bad = format!("import yaml as {al}\ncfg = {al}{sp}.{sp}load{sp}(\n  raw_{i},\n  Loader={al}.Loader\n)\n");
        assert!(scan_text(&yaml_bad, "cfg.py", "python", Severity::Low, None).iter().any(|f| f.scar_id == "KS-020"), "Missed KS-020 #{i}");
        let yaml_ok = format!("import yaml as {al}\ncfg = {al}{sp}.{sp}load{sp}(\n  raw_{i},\n  Loader={al}.SafeLoader\n)\n");
        assert!(!scan_text(&yaml_ok, "cfg_ok.py", "python", Severity::Low, None).iter().any(|f| f.scar_id == "KS-020"));
        sem_cases += 1;

        let os_bad = format!("from os import system as {al}\n{al}{sp}(cmd_{i})\n");
        assert!(scan_text(&os_bad, "exec.py", "python", Severity::Low, None).iter().any(|f| f.scar_id == "KS-022"), "Missed KS-022 #{i}");
        sem_cases += 1;

        let torch_bad = format!("import torch as {al}\nmodel = {al}{sp}.{sp}load{sp}(\n  ckpt_{i}\n)\n");
        assert!(scan_text(&torch_bad, "ml.py", "python", Severity::Low, None).iter().any(|f| f.scar_id == "KS-021"), "Missed KS-021 #{i}");
        let torch_ok = format!("import torch as {al}\nmodel = {al}{sp}.{sp}load{sp}(\n  ckpt_{i},\n  weights_only=True\n)\n");
        assert!(!scan_text(&torch_ok, "ml_ok.py", "python", Severity::Low, None).iter().any(|f| f.scar_id == "KS-021"));
        sem_cases += 1;

        let benign_prose = format!("# Note {i}: The capital sender postponed renewal for customer_{} after review.\n", json_escape(&rng.ascii_word(3, 8)));
        assert!(scan_text(&benign_prose, "notes.md", "markdown", Severity::Low, None).is_empty());
        sem_cases += 1;

        let r = i % 4;
        let hmac_safe = format!(
            "import hmac, hashlib\ndef check_webhook_{i}(secret: bytes, body: bytes, sig: str, retries: int) -> bool:\n    if retries == {r}:\n        return False\n    mac = hmac.new(secret, body, hashlib.sha256).hexdigest()\n    return hmac.compare_digest(mac, sig)\n"
        );
        assert!(!scan_arm_c_shadow_text(&hmac_safe, "webhook.py", "python").iter().any(|f| f.scar_id == "KC-C03"));
        sem_cases += 1;
    }
    assert_eq!(sem_cases, 125);
}
