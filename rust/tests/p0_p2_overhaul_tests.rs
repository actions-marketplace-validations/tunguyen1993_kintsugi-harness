// kintsugi: ignore-file
#![cfg(all(feature = "audit", feature = "rule-ir", feature = "logforge"))]

use std::fs;
use std::io::Read;
use std::process::{Command, Stdio};

use kintsugi_core::kernels::rule_prefilter::builtin_rule_prefilter;
use kintsugi_core::*;

#[test]
fn ks_013_revived_catches_unclosed_browser_launch_and_allows_finally_or_with() {
    let bad_js = "async function scrape() {\n  const browser = await puppeteer.launch();\n  await browser.newPage();\n}\n";
    let f_bad_js = scan_text(bad_js, "job.js", "javascript", Severity::Low, None);
    assert!(
        f_bad_js.iter().any(|f| f.scar_id == "KS-013"),
        "Expected KS-013 on unclosed puppeteer.launch: {:?}",
        f_bad_js
    );

    let good_js = "async function scrape() {\n  const browser = await puppeteer.launch();\n  try {\n    await browser.newPage();\n  } finally {\n    await browser.close();\n  }\n}\n";
    let f_good_js = scan_text(good_js, "job_ok.js", "javascript", Severity::Low, None);
    assert!(
        !f_good_js.iter().any(|f| f.scar_id == "KS-013"),
        "Unexpected KS-013 FP on finally close: {:?}",
        f_good_js
    );

    let bad_py = "def run_pw(p):\n    browser = p.chromium.launch(headless=True)\n    page = browser.new_page()\n    return page.title()\n";
    let f_bad_py = scan_text(bad_py, "pw.py", "python", Severity::Low, None);
    assert!(
        f_bad_py.iter().any(|f| f.scar_id == "KS-013"),
        "Expected KS-013 on unclosed chromium.launch: {:?}",
        f_bad_py
    );

    let good_py = "def run_pw(p):\n    browser = p.chromium.launch(headless=True)\n    try:\n        return browser.new_page().title()\n    finally:\n        browser.close()\n";
    let f_good_py = scan_text(good_py, "pw_ok.py", "python", Severity::Low, None);
    assert!(
        !f_good_py.iter().any(|f| f.scar_id == "KS-013"),
        "Unexpected KS-013 FP on Python finally close: {:?}",
        f_good_py
    );
}

#[test]
fn ks_019_prefilter_ignores_benign_0xe2_punctuation_and_catches_bidi() {
    let pf = builtin_rule_prefilter();
    let benign_unicode = "Báo cáo kỹ thuật — độ trễ giảm 4× … kết quả chuẩn → đạt!\n";
    let mask_benign = pf.candidate_mask_first_word_u64(benign_unicode.as_bytes(), false);
    assert_eq!(
        mask_benign & (1u64 << 18),
        0,
        "Benign 0xE2 punctuation (—, …, →) must NOT trigger KS-019 candidate bit!"
    );

    let bidi_attack = "role = 'user\u{202e}nimda'\n";
    let mask_bidi = pf.candidate_mask_first_word_u64(bidi_attack.as_bytes(), false);
    assert_ne!(mask_bidi & (1u64 << 18), 0, "Real bidi override must set bit 18");
}

#[test]
fn multicore_scan_path_full_is_deterministic_across_20_files() {
    let uniq = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let ws = std::env::temp_dir().join(format!("kintsugi_mc_det_{uniq}"));
    fs::create_dir_all(&ws).unwrap();

    for idx in 0..20 {
        let code = if idx % 3 == 0 {
            format!("import yaml\ndef load_{idx}(raw):\n    return yaml.load(raw, Loader=yaml.Loader)\n")
        } else if idx % 5 == 0 {
            format!("def q_{idx}(cur, u):\n    cur.execute(f\"SELECT * FROM t WHERE name = '{{u}}'\")\n")
        } else {
            format!("def clean_{idx}(x: int) -> int:\n    return x + {idx}\n")
        };
        fs::write(ws.join(format!("mod_{idx:02}.py")), code).unwrap();
    }

    let r1 = scan_path_full(&ws, Severity::Low, None, None, true, None);
    let r2 = scan_path_full(&ws, Severity::Low, None, None, true, None);
    assert_eq!(r1.scanned_files, 20);
    let sig1: Vec<(&str, usize, &str)> = r1
        .findings
        .iter()
        .map(|f| (f.file_path.as_str(), f.line, f.scar_id.as_str()))
        .collect();
    let sig2: Vec<(&str, usize, &str)> = r2
        .findings
        .iter()
        .map(|f| (f.file_path.as_str(), f.line, f.scar_id.as_str()))
        .collect();
    assert_eq!(sig1, sig2, "Multi-core scan_path_full must be 100% deterministic");
    assert!(sig1.iter().any(|&(_, _, id)| id == "KS-020"));
    assert!(sig1.iter().any(|&(_, _, id)| id == "KC-C02"));

    let _ = fs::remove_dir_all(&ws);
}

#[test]
fn dynamic_rule_registry_compiles_rule_ir_at_runtime_without_recompile() {
    let core = "{\"conditions\":{},\"language\":[\"python\"],\"match\":{\"regex\":\"\\\\brequests\\\\s*\\\\.\\\\s*post\\\\s*\\\\([^)]*verify\\\\s*=\\\\s*False\"},\"predicate_kind\":\"bounded_regex\",\"response\":{\"decision\":\"DENY\",\"reason_code\":\"TLS_VERIFY_DISABLED\"},\"severity\":\"HIGH\"}";
    let r_hash = format!("sha256:{}", sha256_hex(core.as_bytes()));
    let rule_json = format!(
        "{{\"schema\":\"RuleIR/1\",\"rule_id\":\"KS-DYN-0001\",\"language\":[\"python\"],\"severity\":\"HIGH\",\"predicate_kind\":\"bounded_regex\",\"match\":{{\"regex\":\"\\\\brequests\\\\s*\\\\.\\\\s*post\\\\s*\\\\([^)]*verify\\\\s*=\\\\s*False\"}},\"conditions\":{{}},\"response\":{{\"decision\":\"DENY\",\"reason_code\":\"TLS_VERIFY_DISABLED\"}},\"rule_hash\":\"{r_hash}\"}}"
    );

    let uniq = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let rules_dir = std::env::temp_dir().join(format!("kintsugi_dyn_rules_{uniq}"));
    fs::create_dir_all(&rules_dir).unwrap();
    fs::write(rules_dir.join("custom_tls.json"), &rule_json).unwrap();

    let reg = DynamicRuleRegistry::load_from_path(&rules_dir).unwrap();
    assert_eq!(reg.len(), 1);

    let hits = reg.scan_buffer(
        "import requests\nrequests.post('https://api.internal', verify=False)\n",
        "client.py",
        "python",
        Severity::High,
    );
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].scar_id, "KS-DYN-0001");

    let clean = reg.scan_buffer(
        "import requests\nrequests.post('https://api.internal', timeout=5)\n",
        "client.py",
        "python",
        Severity::High,
    );
    assert!(clean.is_empty());

    let _ = fs::remove_dir_all(&rules_dir);
}

#[test]
fn cli_gate_zero_bytes_clean_sarif_output_and_broken_pipe_no_panic() {
    let bin = env!("CARGO_BIN_EXE_kintsugi-rs");
    let uniq = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let ws = std::env::temp_dir().join(format!("kintsugi_gate_cli_{uniq}"));
    fs::create_dir_all(&ws).unwrap();
    let clean_py = ws.join("clean.py");
    fs::write(&clean_py, "def add(a: int, b: int) -> int:\n    return a + b\n").unwrap();

    // 1. Clean gate -> 0 bytes stdout, exit 0
    let out_clean = Command::new(bin).arg("gate").arg(&ws).output().unwrap();
    assert_eq!(out_clean.status.code(), Some(0), "{:?}", out_clean);
    assert!(
        out_clean.stdout.is_empty(),
        "Clean gate must emit 0 bytes, got: {:?}",
        String::from_utf8_lossy(&out_clean.stdout)
    );

    // 2. Violation gate -> <80 tokens compact, exit 1
    let vuln_py = ws.join("vuln.py");
    fs::write(
        &vuln_py,
        "def q(cur, x):\n    cur.execute(f\"SELECT * FROM t WHERE k = '{x}'\")\n",
    )
    .unwrap();
    let out_vuln = Command::new(bin).arg("gate").arg(&ws).output().unwrap();
    assert_eq!(out_vuln.status.code(), Some(1));
    let gate_txt = String::from_utf8(out_vuln.stdout).unwrap();
    assert!(gate_txt.contains("KC-C02"), "Expected KC-C02 in gate output: {gate_txt}");
    assert!(estimate_tokens(&gate_txt) <= 80);

    // 3. SARIF 2.1.0 valid JSON output
    let out_sarif = Command::new(bin)
        .args(["gate", "--format", "sarif"])
        .arg(&ws)
        .output()
        .unwrap();
    assert_eq!(out_sarif.status.code(), Some(1));
    let sarif_str = String::from_utf8(out_sarif.stdout).unwrap();
    let parsed_sarif = parse_json_value(&sarif_str).expect("SARIF output must be valid JSON");
    assert_eq!(
        parsed_sarif.as_object().unwrap().get("version").and_then(|v| v.as_str()),
        Some("2.1.0")
    );

    // 4. BrokenPipe test: generate >250KB JSON (>64KB macOS pipe buffer), close reader after 16 bytes -> 0 panic, exit 0
    let big_body = "import yaml\n".to_string() + &"yaml.load(raw, Loader=yaml.Loader)\n".repeat(1200);
    fs::write(ws.join("big_pipe_overflow.py"), big_body).unwrap();
    let mut child = Command::new(bin)
        .args(["scan", "--format", "json"])
        .arg(&ws)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut stdout = child.stdout.take().unwrap();
        let mut tiny = [0u8; 16];
        let _ = stdout.read(&mut tiny);
        drop(stdout); // Immediately close pipe while child still has >200KB left to write!
    }
    let res = child.wait_with_output().unwrap();
    let stderr_str = String::from_utf8_lossy(&res.stderr);
    assert!(
        !stderr_str.contains("panicked"),
        "BrokenPipe must NEVER panic! stderr: {stderr_str}"
    );
    assert_eq!(res.status.code(), Some(0), "BrokenPipe must exit 0 cleanly");

    // 5. KS-S3-03 upgraded SQL ledger DDL coverage (schema-qualified & quoted)
    for sql_ddl in [
        "ALTER TABLE public.ledger_events DISABLE TRIGGER ALL;\n",
        "ALTER TABLE \"ledger_events\" DROP CONSTRAINT pk_ledger;\n",
        "DROP TRIGGER audit_seal ON \"public\".\"ledger_events\";\n",
    ] {
        let hits = scan_text(sql_ddl, "mig.sql", "sql", Severity::High, None);
        assert!(
            hits.iter().any(|h| h.scar_id == "KS-S3-03"),
            "Expected KS-S3-03 on {sql_ddl:?}, got {hits:?}"
        );
    }

    let _ = fs::remove_dir_all(&ws);
}

#[test]
fn git_diff_confinement_overflow_fail_closed_staged_and_ffi_overlap_guards() {
    let repo = std::path::Path::new("/repo");
    let adversarial_diff = "\
--- a//etc/passwd\n\
+++ b//etc/passwd\n\
@@ -1,1 +1,3 @@\n\
--- a/a/../secret.py\n\
+++ b/a/../secret.py\n\
@@ -1,1 +1,2 @@\n\
+++ b/src/spoofed_without_minus_header.py\n\
@@ -1,1 +1,2 @@\n\
--- a/src/foo..bar.py\n\
+++ b/src/foo..bar.py\n\
@@ -1,1 +10,2 @@\n\
--- a/src/overflow.py\n\
+++ b/src/overflow.py\n\
@@ -1,1 +18446744073709551614,999999999 @@\n";

    let parsed = parse_git_diff_lines(adversarial_diff, repo);
    assert!(!parsed.contains_key(std::path::Path::new("/etc/passwd")), "Must block b//etc/passwd escape!");
    assert!(!parsed.contains_key(&repo.join("src/spoofed_without_minus_header.py")), "Must reject +++ without preceding --- header!");
    assert!(parsed.keys().all(|p| p.starts_with(repo)), "All parsed paths must stay inside repo_root!");
    assert!(parsed.contains_key(&repo.join("src/foo..bar.py")), "Valid double-dot filename must be allowed!");
    assert!(parsed.get(&repo.join("src/overflow.py")).unwrap().len() <= 2, "Overflowing hunk must saturate safely!");

    // Fail-closed staged scan outside a Git repository
    let uniq = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let non_git = std::env::temp_dir().join(format!("kintsugi_non_git_{uniq}"));
    fs::create_dir_all(&non_git).unwrap();
    let staged_sum = scan_git_staged(&non_git, Severity::High);
    assert!(
        staged_sum.findings.iter().any(|f| f.scar_id == "KS-GIT-STAGED-FAILED"),
        "Staged scan outside git repo must fail closed, got: {:?}",
        staged_sum.findings
    );
    let _ = fs::remove_dir_all(&non_git);

    // FFI overlapping input/output buffer rejection (`KINTSUGI_FFI_ERR_INVALID_ARG` = -4)
    let mut shared = [b'a'; 128];
    // SAFETY: `shared` is a live 128-byte stack array. The input range [0, 32) and the output
    // range [0, 65) both fit inside it. The overlap is intentional: the FFI must reject it with
    // INVALID_ARG before it dereferences either pointer.
    let rc_overlap = unsafe { ffi::kintsugi_sha256_v1(shared.as_ptr(), 32, shared.as_mut_ptr(), 65) };
    assert_eq!(rc_overlap, ffi::KINTSUGI_FFI_ERR_INVALID_ARG);
}

#[test]
fn sprint_closures_dom_pretool_regex_failclosed_sql_comments_and_strict_cli() {
    // 1. P0-1: PreToolUse DOM JSON parser allows escaped `"tool_input": []` and `"cwd": "/etc"` inside benign content!
    let benign_write = r#"{"tool_name":"Write","tool_input":{"file_path":"docs/guide.md","content":"Example schema: \"tool_input\": [] and \"cwd\": \"/etc\" in prose.\n"}}"#;
    let dec_allow = evaluate_pre_tool_json(benign_write, Severity::High);
    assert!(
        dec_allow.contains("\"permissionDecision\":\"allow\""),
        "DOM PreTool parser must NOT false-deny escaped keys inside content string: {dec_allow}"
    );

    // Malformed trailing-comma JSON must be denied fail-closed
    let malformed = "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"echo ok\",}}";
    let dec_deny = evaluate_pre_tool_json(malformed, Severity::High);
    assert!(dec_deny.contains("\"permissionDecision\":\"deny\""), "{dec_deny}");

    // 2. P0-3: BoundedRegex try_find_all fails closed on step-limit exhaustion instead of returning Ok([])
    let tricky_rx = BoundedRegex::compile("(a+)+b").unwrap();
    let adversarial_text = "a".repeat(220) + "c";
    assert!(
        tricky_rx.try_find_all(&adversarial_text).is_err(),
        "Adversarial backtracking must return Err fail-closed in try_find_all"
    );

    // 3. KS-013 nested brace scope: `.close()` AFTER `finally` closes inside outer `if` must STILL be caught!
    let bad_nested_js = "async function run(flag) {\n  if (flag) {\n    const browser = await puppeteer.launch();\n    try {\n      await browser.newPage();\n    } finally {\n      console.log('cleanup without closing');\n    }\n    await browser.close();\n  }\n}\n";
    let f_nested = scan_text(bad_nested_js, "nested.js", "javascript", Severity::Low, None);
    assert!(
        f_nested.iter().any(|f| f.scar_id == "KS-013"),
        "close() outside finally inside outer if-block must be caught as KS-013: {f_nested:?}"
    );

    // 4. KS-S3-03 ignores SQL `--` comments and single-quoted string literals
    assert!(scan_text("-- ALTER TABLE public.ledger_events DROP COLUMN x;\n", "c.sql", "sql", Severity::High, None).is_empty());
    assert!(scan_text("SELECT 'ALTER TABLE public.ledger_events';\n", "q.sql", "sql", Severity::High, None).is_empty());

    // 5. Strict CLI validation rejects invalid --fail-on and invalid --sub-cap with exit code 2
    let bin = env!("CARGO_BIN_EXE_kintsugi-rs");
    let bad_sev = Command::new(bin).args(["gate", "--fail-on", "NOT_A_SEV"]).output().unwrap();
    assert_eq!(bad_sev.status.code(), Some(2));
    let bad_num = Command::new(bin).args(["step-audit", "--sub-cap", "abc"]).output().unwrap();
    assert_eq!(bad_num.status.code(), Some(2));
}

