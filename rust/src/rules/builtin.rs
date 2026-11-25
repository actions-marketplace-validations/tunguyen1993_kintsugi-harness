// kintsugi: ignore-file
//! Static catalogs for the 36 `BUILTIN_RULES` and 5 `ARM_C_SHADOW_RULES`.

use crate::model::{NativeRule, Severity};

pub const BUILTIN_RULES: &[NativeRule] = &[
    NativeRule {
        id: "KS-001",
        title: "@OP/1[ID:KS-001|SEV:CRITICAL|CAT:security|LANG:py,js,ts,go,rs,sh|OP:secret!=literal->os.environ]",
        severity: Severity::Critical,
        category: "security",
        kmi_token: "KS-001(secret!=literal->os.environ)",
        languages: &["python", "javascript", "typescript", "go", "rust", "shell"],
        fix_hint: "@POS_AST{api_key = os.environ[\"SERVICE_API_KEY\"]}",
        premium_only: false,
    },
    NativeRule {
        id: "KS-002",
        title: "@OP/1[ID:KS-002|SEV:CRITICAL|CAT:security|LANG:py|OP:subprocess!shell=True->argv_list]",
        severity: Severity::Critical,
        category: "security",
        kmi_token: "KS-002(subprocess!shell=True->argv_list)",
        languages: &["python"],
        fix_hint: "@POS_AST{subprocess.run([\"git\", \"status\"], shell=False, check=True)}",
        premium_only: false,
    },
    NativeRule {
        id: "KS-003",
        title: "@OP/1[ID:KS-003|SEV:CRITICAL|CAT:security|LANG:py,js,ts|OP:no_eval_exec_pickle->literal_eval]",
        severity: Severity::Critical,
        category: "security",
        kmi_token: "KS-003(no_eval_exec_pickle->literal_eval)",
        languages: &["python", "javascript", "typescript"],
        fix_hint: "@POS_AST{data = json.loads(raw_payload)}",
        premium_only: false,
    },
    NativeRule {
        id: "KS-004",
        title: "@OP/1[ID:KS-004|SEV:HIGH|CAT:correctness|LANG:py|OP:py!mutable_default->None]",
        severity: Severity::High,
        category: "correctness",
        kmi_token: "KS-004(py!mutable_default->None)",
        languages: &["python"],
        fix_hint: "@POS_AST{def append_item(item: str, bucket: list[str] | None = None):}",
        premium_only: false,
    },
    NativeRule {
        id: "KS-005",
        title: "@OP/1[ID:KS-005|SEV:HIGH|CAT:reliability|LANG:py|OP:py!bare_except_pass->log_raise]",
        severity: Severity::High,
        category: "reliability",
        kmi_token: "KS-005(py!bare_except_pass->log_raise)",
        languages: &["python"],
        fix_hint: "@POS_AST{except Exception as exc: logger.exception(\"%s\", exc); raise}",
        premium_only: false,
    },
    NativeRule {
        id: "KS-006",
        title: "@OP/1[ID:KS-006|SEV:HIGH|CAT:reliability|LANG:py|OP:http!missing_timeout->timeout=10]",
        severity: Severity::High,
        category: "reliability",
        kmi_token: "KS-006(http!missing_timeout->timeout=10)",
        languages: &["python"],
        fix_hint: "@POS_AST{resp = requests.get(url, timeout=10)}",
        premium_only: false,
    },
    NativeRule {
        id: "KS-007",
        title: "@OP/1[ID:KS-007|SEV:CRITICAL|CAT:security|LANG:py,js,ts|OP:sql!fstring->param_query]",
        severity: Severity::Critical,
        category: "security",
        kmi_token: "KS-007(sql!fstring->param_query)",
        languages: &["python", "javascript", "typescript"],
        fix_hint: "@POS_AST{cursor.execute(\"SELECT * FROM users WHERE email = ?\", (email,))}",
        premium_only: false,
    },
    NativeRule {
        id: "KS-008",
        title: "@OP/1[ID:KS-008|SEV:HIGH|CAT:security|LANG:py|OP:crypto!random->secrets.token_urlsafe]",
        severity: Severity::High,
        category: "security",
        kmi_token: "KS-008(crypto!random->secrets.token_urlsafe)",
        languages: &["python"],
        fix_hint: "@POS_AST{reset_token = secrets.token_urlsafe(32)}",
        premium_only: false,
    },
    NativeRule {
        id: "KS-009",
        title: "@OP/1[ID:KS-009|SEV:MEDIUM|CAT:quality|LANG:py,js,ts,go,rs|OP:no_todo_placeholder_stub]",
        severity: Severity::Medium,
        category: "quality",
        kmi_token: "KS-009(no_todo_placeholder_stub)",
        languages: &["python", "javascript", "typescript", "go", "rust"],
        fix_hint: "@POS_AST{implement_concrete_production_logic()}",
        premium_only: false,
    },
    NativeRule {
        id: "KS-010",
        title: "@OP/1[ID:KS-010|SEV:MEDIUM|CAT:reliability|LANG:py|OP:audit!no_truncate_overwrite->append]",
        severity: Severity::Medium,
        category: "reliability",
        kmi_token: "KS-010(audit!no_truncate_overwrite->append)",
        languages: &["python"],
        fix_hint: "@POS_AST{with open(audit_log_path, \"a\", encoding=\"utf-8\") as f:}",
        premium_only: false,
    },
    NativeRule {
        id: "KS-011",
        title: "@OP/1[ID:KS-011|SEV:HIGH|CAT:security|LANG:py,js,ts|OP:tls!verify=False->verify=True]",
        severity: Severity::High,
        category: "security",
        kmi_token: "KS-011(tls!verify=False->verify=True)",
        languages: &["python", "javascript", "typescript"],
        fix_hint: "@POS_AST{requests.get(url, verify=True, timeout=10)}",
        premium_only: false,
    },
    NativeRule {
        id: "KS-012",
        title: "@OP/1[ID:KS-012|SEV:HIGH|CAT:security|LANG:js,ts|OP:dom!innerHTML->textContent]",
        severity: Severity::High,
        category: "security",
        kmi_token: "KS-012(dom!innerHTML->textContent)",
        languages: &["javascript", "typescript"],
        fix_hint: "@POS_AST{panel.textContent = userComment;}",
        premium_only: false,
    },
    NativeRule {
        id: "KS-013",
        title: "@OP/1[ID:KS-013|SEV:MEDIUM|CAT:reliability|LANG:js,ts,py|OP:browser!launch->close_in_finally]",
        severity: Severity::Medium,
        category: "reliability",
        kmi_token: "KS-013(browser!launch->close_in_finally)",
        languages: &["javascript", "typescript", "python"],
        fix_hint: "@POS_AST{try { ... } finally { await browser.close(); }}",
        premium_only: false,
    },
    NativeRule {
        id: "KS-014",
        title: "@OP/1[ID:KS-014|SEV:CRITICAL|CAT:safety|LANG:sh,py,js,ts|OP:sh!no_force_push_or_rm_rf_root]",
        severity: Severity::Critical,
        category: "safety",
        kmi_token: "KS-014(sh!no_force_push_or_rm_rf_root)",
        languages: &["shell", "python", "javascript", "typescript"],
        fix_hint: "@POS_AST{git push --force-with-lease origin main}",
        premium_only: false,
    },
    NativeRule {
        id: "KS-015",
        title: "@OP/1[ID:KS-015|SEV:HIGH|CAT:reliability|LANG:go,py,js,ts|OP:go!no_blank_error_or_cors_wildcard]",
        severity: Severity::High,
        category: "reliability",
        kmi_token: "KS-015(go!no_blank_error_or_cors_wildcard)",
        languages: &["go", "python", "javascript", "typescript"],
        fix_hint: "@POS_AST{if err := json.Unmarshal(payload, &cfg); err != nil { return err }}",
        premium_only: false,
    },
    NativeRule {
        id: "KS-016",
        title: "@OP/1[ID:KS-016|SEV:HIGH|CAT:security|LANG:py,js,ts,go|OP:ssrf!allowlist_https_scheme]",
        severity: Severity::High,
        category: "security",
        kmi_token: "KS-016(ssrf!allowlist_https_scheme)",
        languages: &["python", "javascript", "typescript", "go"],
        fix_hint: "@POS_AST{assert parsed.scheme == 'https' and host != '169.254.169.254'}",
        premium_only: false,
    },
    NativeRule {
        id: "KS-017",
        title: "@OP/1[ID:KS-017|SEV:CRITICAL|CAT:security|LANG:py|OP:tar!extractall->filter='data']",
        severity: Severity::Critical,
        category: "security",
        kmi_token: "KS-017(tar!extractall->filter='data')",
        languages: &["python"],
        fix_hint: "@POS_AST{tar.extractall(path=dest_dir, filter=\"data\")}",
        premium_only: false,
    },
    NativeRule {
        id: "KS-018",
        title: "@OP/1[ID:KS-018|SEV:MEDIUM|CAT:reliability|LANG:dockerfile,sh|OP:docker!no_latest->pin_sha256]",
        severity: Severity::Medium,
        category: "reliability",
        kmi_token: "KS-018(docker!no_latest->pin_sha256)",
        languages: &["dockerfile", "shell"],
        fix_hint: "@POS_AST{FROM python:3.12-slim@sha256:4c100f870...}",
        premium_only: false,
    },
    NativeRule {
        id: "KS-019",
        title: "@OP/1[ID:KS-019|SEV:CRITICAL|CAT:mcp-prompt-security|LANG:py,js,ts,rs,go,sh|OP:bidi_unicode!strip_trojan_source]",
        severity: Severity::Critical,
        category: "mcp-prompt-security",
        kmi_token: "KS-019(bidi_unicode!strip_trojan_source)",
        languages: &["python", "javascript", "typescript", "rust", "go", "shell"],
        fix_hint: "@POS_AST{assert !text.chars().any(is_bidi_control)}",
        premium_only: true,
    },
    NativeRule {
        id: "KS-020",
        title: "@OP/1[ID:KS-020|SEV:CRITICAL|CAT:security|LANG:py|OP:yaml!load->safe_load]",
        severity: Severity::Critical,
        category: "security",
        kmi_token: "KS-020(yaml!load->safe_load)",
        languages: &["python"],
        fix_hint: "@POS_AST{cfg = yaml.safe_load(raw_yaml_payload)}",
        premium_only: true,
    },
    NativeRule {
        id: "KS-021",
        title: "@OP/1[ID:KS-021|SEV:CRITICAL|CAT:security|LANG:py|OP:torch!load->weights_only=True]",
        severity: Severity::Critical,
        category: "security",
        kmi_token: "KS-021(torch!load->weights_only=True)",
        languages: &["python"],
        fix_hint: "@POS_AST{state_dict = torch.load(path, weights_only=True)}",
        premium_only: true,
    },
    NativeRule {
        id: "KS-022",
        title: "@OP/1[ID:KS-022|SEV:CRITICAL|CAT:mcp-prompt-security|LANG:py|OP:os.system!interp->subprocess_argv]",
        severity: Severity::Critical,
        category: "mcp-prompt-security",
        kmi_token: "KS-022(os.system!interp->subprocess_argv)",
        languages: &["python"],
        fix_hint: "@POS_AST{subprocess.run([\"cmd\", arg], shell=False, check=True)}",
        premium_only: true,
    },
    NativeRule {
        id: "KS-023",
        title: "@OP/1[ID:KS-023|SEV:HIGH|CAT:security|LANG:py,rs|OP:xml!no_resolve_entities_or_transmute]",
        severity: Severity::High,
        category: "security",
        kmi_token: "KS-023(xml!no_resolve_entities_or_transmute)",
        languages: &["python", "rust"],
        fix_hint: "@POS_AST{etree.XMLParser(resolve_entities=False, no_network=True)}",
        premium_only: true,
    },
    NativeRule {
        id: "KS-024",
        title: "@OP/1[ID:KS-024|SEV:CRITICAL|CAT:security|LANG:py,js,ts|OP:jwt!verify_signature=True]",
        severity: Severity::Critical,
        category: "security",
        kmi_token: "KS-024(jwt!verify_signature=True)",
        languages: &["python", "javascript", "typescript"],
        fix_hint: "@POS_AST{jwt.decode(token, pub_key, algorithms=[\"RS256\"])}",
        premium_only: true,
    },
    NativeRule {
        id: "KS-025",
        title: "@OP/1[ID:KS-025|SEV:CRITICAL|CAT:security|LANG:py,js,ts,go,rs,sh|OP:pem!no_embedded_private_key]",
        severity: Severity::Critical,
        category: "security",
        kmi_token: "KS-025(pem!no_embedded_private_key)",
        languages: &["python", "javascript", "typescript", "go", "rust", "shell"],
        fix_hint: "@POS_AST{key = fs::read_to_string(env::var(\"SIGNING_KEY_PATH\")?)}",
        premium_only: true,
    },
    NativeRule {
        id: "KS-026",
        title: "@OP/1[ID:KS-026|SEV:HIGH|CAT:agent-finops|LANG:py,js,ts|OP:loop!bounded_max_steps]",
        severity: Severity::High,
        category: "agent-finops",
        kmi_token: "KS-026(loop!bounded_max_steps)",
        languages: &["python", "javascript", "typescript"],
        fix_hint: "@POS_AST{for step in range(MAX_AGENT_STEPS):}",
        premium_only: true,
    },
    NativeRule {
        id: "KS-027",
        title: "@OP/1[ID:KS-027|SEV:HIGH|CAT:security|LANG:py,js,ts|OP:hmac!constant_time_compare_digest]",
        severity: Severity::High,
        category: "security",
        kmi_token: "KS-027(hmac!constant_time_compare_digest)",
        languages: &["python", "javascript", "typescript"],
        fix_hint: "@POS_AST{hmac.compare_digest(webhook_signature, expected_hmac_digest)}",
        premium_only: true,
    },
    NativeRule {
        id: "KS-028",
        title: "@OP/1[ID:KS-028|SEV:CRITICAL|CAT:security|LANG:js,ts|OP:node!execSync_template->execFileSync]",
        severity: Severity::Critical,
        category: "security",
        kmi_token: "KS-028(node!execSync_template->execFileSync)",
        languages: &["javascript", "typescript"],
        fix_hint: "@POS_AST{execFileSync(\"git\", [\"checkout\", branch])}",
        premium_only: true,
    },
    NativeRule {
        id: "KS-029",
        title: "@OP/1[ID:KS-029|SEV:MEDIUM|CAT:container-security|LANG:dockerfile,sh|OP:chmod!no_777->750]",
        severity: Severity::Medium,
        category: "container-security",
        kmi_token: "KS-029(chmod!no_777->750)",
        languages: &["dockerfile", "shell"],
        fix_hint: "@POS_AST{chmod 750 /app/data}",
        premium_only: true,
    },
    NativeRule {
        id: "KS-030",
        title: "@OP/1[ID:KS-030|SEV:HIGH|CAT:reliability|LANG:py|OP:async!no_blocking_time_sleep]",
        severity: Severity::High,
        category: "reliability",
        kmi_token: "KS-030(async!no_blocking_time_sleep)",
        languages: &["python"],
        fix_hint: "@POS_AST{await asyncio.sleep(delay)}",
        premium_only: true,
    },
    NativeRule {
        id: "KS-031",
        title: "@OP/1[ID:KS-031|SEV:MEDIUM|CAT:reliability|LANG:py|OP:tempfile!mktemp->mkstemp]",
        severity: Severity::Medium,
        category: "reliability",
        kmi_token: "KS-031(tempfile!mktemp->mkstemp)",
        languages: &["python"],
        fix_hint: "@POS_AST{fd, tmp_path = tempfile.mkstemp(suffix=\".json\")}",
        premium_only: true,
    },
    NativeRule {
        id: "KS-032",
        title: "@OP/1[ID:KS-032|SEV:HIGH|CAT:security|LANG:py,sh,js,ts|OP:ssh!StrictHostKeyChecking=yes]",
        severity: Severity::High,
        category: "security",
        kmi_token: "KS-032(ssh!StrictHostKeyChecking=yes)",
        languages: &["python", "shell", "javascript", "typescript"],
        fix_hint: "@POS_AST{ssh -o StrictHostKeyChecking=yes user@host}",
        premium_only: true,
    },
    NativeRule {
        id: "KS-S3-01",
        title: "@OP/1[ID:KS-S3-01|SEV:CRITICAL|CAT:s3-security|LANG:py,js,ts,sh,rs,md|OP:s3!no_chatml_prompt_override]",
        severity: Severity::Critical,
        category: "s3-security",
        kmi_token: "KS-S3-01(s3!no_chatml_prompt_override)",
        languages: &["python", "javascript", "typescript", "shell", "rust", "markdown"],
        fix_hint: "@POS_AST{sanitize_external_untrusted_text(payload)}",
        premium_only: true,
    },
    NativeRule {
        id: "KS-S3-02",
        title: "@OP/1[ID:KS-S3-02|SEV:CRITICAL|CAT:s3-security|LANG:sh,py,js,ts|OP:s3!allowlisted_ssh_no_hex_ip_or_tunnel]",
        severity: Severity::Critical,
        category: "s3-security",
        kmi_token: "KS-S3-02(s3!allowlisted_ssh_no_hex_ip_or_tunnel)",
        languages: &["shell", "python", "javascript", "typescript"],
        fix_hint: "@POS_AST{ssh -o StrictHostKeyChecking=yes user@allowlisted-host.internal}",
        premium_only: true,
    },
    NativeRule {
        id: "KS-S3-03",
        title: "@OP/1[ID:KS-S3-03|SEV:CRITICAL|CAT:s3-db-migration|LANG:ts,js,py|OP:db!no_blocking_ddl_on_partitioned_ledger]",
        severity: Severity::Critical,
        category: "s3-db-migration",
        kmi_token: "KS-S3-03(db!no_blocking_ddl_on_partitioned_ledger)",
        languages: &["typescript", "javascript", "python", "sql"],
        fix_hint: "@POS_AST{/* Never run unconcurrent CREATE INDEX / ALTER TABLE on hot ledger tables in app migrations */}",
        premium_only: true,
    },
    NativeRule {
        id: "KS-S3-04",
        title: "@OP/1[ID:KS-S3-04|SEV:CRITICAL|CAT:s3-pii-fence|LANG:js,ts,py,sh|OP:pii!no_raw_private_credential_or_dotenv_read]",
        severity: Severity::Critical,
        category: "s3-pii-fence",
        kmi_token: "KS-S3-04(pii!no_raw_private_credential_or_dotenv_read)",
        languages: &["javascript", "typescript", "python", "shell"],
        fix_hint: "@POS_AST{readSanitizedOutboundFileS3(resolvedPath, workspaceRoot)}",
        premium_only: true,
    },
];

pub const ARM_C_SHADOW_RULES: &[NativeRule] = &[
    NativeRule {
        id: "KC-C01",
        title: "@OP/1[ID:KC-C01|SEV:HIGH|CAT:security|LANG:py|OP:git!option_injection->'--'_or_startswith('-')_guard]",
        severity: Severity::High,
        category: "security",
        kmi_token: "KC-C01(git!option_injection->'--'_guard)",
        languages: &["python"],
        fix_hint: "@POS_AST{Use '--' before dynamic git args AND reject leading '-', NUL, and shell metachars}",
        premium_only: false,
    },
    NativeRule {
        id: "KC-C02",
        title: "@OP/1[ID:KC-C02|SEV:HIGH|CAT:security|LANG:py|OP:sql!interp_fstring_pct_format->param_query]",
        severity: Severity::High,
        category: "security",
        kmi_token: "KC-C02(sql!interp->param_query)",
        languages: &["python"],
        fix_hint: "@POS_AST{Use parameterized SQL placeholders (?, %s) instead of f-string/%/.format interpolation}",
        premium_only: false,
    },
    NativeRule {
        id: "KC-C03",
        title: "@OP/1[ID:KC-C03|SEV:HIGH|CAT:security|LANG:py|OP:hmac!eq_cmp->hmac.compare_digest]",
        severity: Severity::High,
        category: "security",
        kmi_token: "KC-C03(hmac!eq->hmac.compare_digest)",
        languages: &["python"],
        fix_hint: "@POS_AST{Use hmac.compare_digest(a, b) instead of == or != for HMAC digests}",
        premium_only: false,
    },
    NativeRule {
        id: "KC-C04",
        title: "@OP/1[ID:KC-C04|SEV:MEDIUM|CAT:security|LANG:py|OP:sensitive_open!no_O_NOFOLLOW->open_nofollow]",
        severity: Severity::Medium,
        category: "security",
        kmi_token: "KC-C04(sensitive_open!O_NOFOLLOW)",
        languages: &["python"],
        fix_hint: "@POS_AST{Open sensitive key/manifest/secret/policy/registry files via os.O_NOFOLLOW}",
        premium_only: false,
    },
    NativeRule {
        id: "KC-C05",
        title: "@OP/1[ID:KC-C05|SEV:HIGH|CAT:integrity|LANG:py|OP:ablation!bool_coerce->type_is_bool]",
        severity: Severity::High,
        category: "integrity",
        kmi_token: "KC-C05(ablation!bool_coerce->strict_bool)",
        languages: &["python"],
        fix_hint: "@POS_AST{Validate ablation bool fields with type(val) is bool instead of bool(data[...])}",
        premium_only: false,
    },
];

const fn const_str_eq(a: &str, b: &str) -> bool {
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    if ab.len() != bb.len() { return false; }
    let mut i = 0;
    while i < ab.len() {
        if ab[i] != bb[i] { return false; }
        i += 1;
    }
    true
}

/// Compile-time lookup of a rule's slot index in `BUILTIN_RULES` (panics at compile time if `id` is absent).
pub const fn builtin_rule_index(id: &str) -> usize {
    let mut idx = 0;
    while idx < BUILTIN_RULES.len() {
        if const_str_eq(BUILTIN_RULES[idx].id, id) { return idx; }
        idx += 1;
    }
    panic!("unknown BUILTIN_RULES rule id")
}

/// Compile-time bitmask builder over `BUILTIN_RULES` IDs (`0..64`).
pub const fn builtin_rule_mask(ids: &[&str]) -> u64 {
    let (mut mask, mut i) = (0u64, 0usize);
    while i < ids.len() {
        let idx = builtin_rule_index(ids[i]);
        assert!(idx < 64, "BUILTIN_RULES index exceeds 64-bit mask");
        mask |= 1u64 << idx;
        i += 1;
    }
    mask
}

pub const IDX_KS_009: usize = builtin_rule_index("KS-009");
pub const IDX_KS_013: usize = builtin_rule_index("KS-013");
pub const IDX_KS_014: usize = builtin_rule_index("KS-014");
pub const IDX_KS_019: usize = builtin_rule_index("KS-019");
pub const IDX_KS_026: usize = builtin_rule_index("KS-026");
pub const IDX_KS_029: usize = builtin_rule_index("KS-029");
pub const IDX_KS_030: usize = builtin_rule_index("KS-030");
pub const IDX_KS_S3_01: usize = builtin_rule_index("KS-S3-01");
pub const IDX_KS_S3_03: usize = builtin_rule_index("KS-S3-03");
pub const COMMENT_SCANNABLE_RULE_MASK: u64 = builtin_rule_mask(&["KS-009", "KS-026", "KS-030"]);
pub const ALIAS_CALL_RULE_MASK: u64 = builtin_rule_mask(&[
    "KS-002", "KS-003", "KS-006", "KS-017", "KS-020", "KS-021", "KS-022", "KS-024", "KS-028", "KS-031",
]);
