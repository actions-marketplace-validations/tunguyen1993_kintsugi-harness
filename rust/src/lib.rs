// kintsugi: ignore-file
//! Kintsugi Core (`kintsugi_core` v3.0.0) — Zero-dependency modular Rust scanner,
//! Flat-CSR SIMD prefilter, Multi-core deterministic repo walker, Feature-Gated
//! `RuleIR/1` & `@CT2` Grade-S3 Seam Auditor, Agent-Native `gate` formatters, and C-ABI FFI.
//!
//! ## Two-Tier SemVer Contract
//! **Tier 1: Public, SemVer-stable.** Only these two surfaces are covered by SemVer:
//! - [`prelude`] (`kintsugi_core::prelude::*`): exactly 9 symbols (`Finding`, `NativeRule`,
//!   `ScanSummary`, `Severity`, `scan_git_staged`, `scan_path`, `scan_text`, `BUILTIN_RULES`,
//!   `ENGINE_VERSION`).
//! - The versioned C-ABI in [`ffi`] (`ffi::kintsugi_*` symbols, `kintsugi_abi_version() == 1`).
//!
//! **Tier 2: Crate-internal plumbing, exempt from SemVer.** All other domain modules
//! (`scanner`, `rules`, `parsers`, `policy`, `unicode_policy`, `output`, `io_json`, `json_dom`,
//! `kernels`, `kml`, `model`, `token_est`, `bounded_regex`, plus the feature-gated `audit`,
//! `rule_ir`, `dynamic_rules`) and every root re-export marked `#[doc(hidden)]` exist only to
//! serve the `kintsugi-rs` CLI and the integration tests. They may change or be removed in any
//! release, including patch releases, without notice.

#[cfg(feature = "audit")]
pub mod audit;
pub mod bounded_regex;
#[cfg(feature = "rule-ir")]
pub mod dynamic_rules;
pub mod ffi;
pub mod io_json;
pub mod json_dom;
pub mod kernels;
pub mod kml;
pub mod model;
pub mod output;
pub mod parsers;
pub mod policy;
#[cfg(feature = "rule-ir")]
pub mod rule_ir;
pub mod rules;
pub mod scanner;
pub mod token_est;
pub mod unicode_policy;

/// Minimal, semver-stable embedding prelude for `kintsugi_core`.
pub mod prelude {
    pub use crate::io_json::ENGINE_VERSION;
    pub use crate::model::{Finding, NativeRule, ScanSummary, Severity};
    pub use crate::rules::BUILTIN_RULES;
    pub use crate::scanner::{scan_git_staged, scan_path, scan_text};
}

pub use prelude::*;

// ---------------------------------------------------------------------------
// Tier 2: crate-internal plumbing (NOT SemVer-stable)
// ---------------------------------------------------------------------------
// Every `#[doc(hidden)]` re-export below exists only for the `kintsugi-rs` CLI and the
// integration tests under `rust/tests/`. None of it is covered by SemVer. External embedders
// must use `kintsugi_core::prelude::*` or the `ffi::kintsugi_*` C-ABI only.

#[cfg(feature = "audit")]
#[doc(hidden)]
pub use audit::{
    audit_step_economics_files, audit_step_economics_path, build_context_envelope_for_file,
    build_context_envelope_for_source, builtin_invariant_capsules, compute_s3_verdicts,
    compute_token_benchmark, evaluate_post_read_hook_json, evaluate_pre_tool_detailed,
    evaluate_pre_tool_json, evaluate_pre_tool_json_with_workspace, extract_code_capsule_signals,
    extract_symbol_blocks, load_custom_capsules_json, match_capsules_for_file,
    match_capsules_for_source, match_low_tier_lexicon_for_file, match_low_tier_lexicon_for_source,
    prove_file_obligations, push_ident_subtokens, render_all_lexicon_json,
    render_capsule_report_json, render_context_envelope_json, render_creed_json,
    render_kmi_compact_header, render_lexicon_report_json, render_memories_verify_json,
    render_s3_audit_json, render_step_audit_json, render_swarm_plan_json,
    render_verbose_guardrail_manual, s3_audit_file, s3_audit_file_with_mode, s3_audit_path,
    s3_audit_path_with_mode, verify_memories_readonly, CapsuleMatchReport, ContextEnvelope,
    FailingSeam, HookEvaluation, InvariantCapsule, LexiconMatchReport, MemoriesVerifyReport,
    Obligation, ObligationState, PitfallEntry, S3AuditSummary, S3FileAudit, SeamEvidence, Span,
    StatefulMasker, StepAuditReport, SymbolBlock, CONTEXT_ENVELOPE_SCHEMA,
    DEFAULT_ENVELOPE_MAX_TOKENS, LOW_TIER_PITFALL_LEXICON, MEMORIES_ENFORCEMENT_MODE,
    MEMORIES_READ_ONLY_BEHAVIOR, OBLIGATION_PROVER_KIND, S3_AUDITOR_KIND, S3_EVIDENCE_MODEL,
};
#[doc(hidden)]
pub use bounded_regex::{
    BoundedRegex, RegexError, DEFAULT_MAX_STEPS_PER_POS, MAX_REGEX_NODES, MAX_REGEX_RECURSION_DEPTH,
};
#[cfg(feature = "rule-ir")]
#[doc(hidden)]
pub use dynamic_rules::{
    DynamicRuleRegistry, MAX_DYNAMIC_FINDINGS_PER_FILE, MAX_DYNAMIC_RULES,
    MAX_DYNAMIC_RULE_FILE_BYTES, MAX_DYNAMIC_STEPS_PER_SCAN,
};
#[doc(hidden)]
pub use io_json::{
    fnv1a_64, fnv1a_64_hex, json_escape, json_escape_into, read_regular_bytes_fd_verified,
    read_regular_file_fd_verified, read_stdin_checked, try_write_stdout_bytes, write_stderr_safe,
    write_stdout_bytes, write_stdout_ln, write_stdout_outcome, write_stdout_str, JsonArr, JsonObj,
    RawJson, WriteOutcome, FNV1A_64_INIT, MAX_STDIN_BYTES,
};
#[doc(hidden)]
pub use json_dom::{
    compute_rule_ir_canonical_hash, parse_json_value, write_canonical_json_str, JsonValue,
    MAX_JSON_DEPTH,
};
#[doc(hidden)]
pub use kml::{
    audit_kml_record_security, infer_kml_lang_from_path, inspect_kml_corpus_file, parse_kml_corpus,
    render_kml_builtin_corpus, render_kml_builtin_corpus_for_lang, verify_outbound_destination_allowed,
    KmlCorpusReport, KmlRecord,
    ALLOWED_OUTBOUND_GIT_REMOTES, ALLOWED_PUBLIC_EVOLUTION_REPO,
};
#[doc(hidden)]
pub use model::TokenBenchmark;
#[cfg(feature = "sarif")]
#[doc(hidden)]
pub use output::render_findings_sarif;
#[doc(hidden)]
pub use output::{
    deduplicate_findings, render_findings_json_array, render_findings_jsonl, render_gate_compact,
    render_gate_compact_detailed, render_scan_json, render_scan_json_with_meta,
    render_scan_summary_json, RenderedGate,
};
#[doc(hidden)]
pub use parsers::{
    evaluate_arm_c_shadow_rule, scan_arm_c_shadow_text, scan_arm_c_shadow_text_with_options,
};
#[doc(hidden)]
pub use policy::{
    audit_shell_command_argv, audit_shell_command_argv_with_ws, classify_workspace_rel_path_opt,
    find_enclosing_repo_root, is_dangerous_rm_target, is_dangerous_rm_target_with_ws,
    is_dangerous_rm_target_with_ws_opt, load_trusted_policy_files_explicit_sha, sha256_hex,
};
#[cfg(feature = "rule-ir")]
#[doc(hidden)]
pub use rule_ir::{
    compile_rule_ir_strict, evaluate_rule_ir_json, evaluate_rule_ir_json_no_fs,
    validate_rule_ir_json, validate_rule_ir_json_strict, CompiledPredicate, CompiledRuleIr,
    NoFsPathPolicy, PathPolicyEvaluator, WorkspacePathPolicy,
};
#[doc(hidden)]
pub use rules::{
    check_ks013_with_lines, check_line_against_rule, check_line_against_rule_lang,
    check_line_against_rule_lang_with_ctx, check_line_against_rule_with_aliases,
    contains_bidi_control, contains_bidi_control_at_line, contains_prompt_injection_text,
    detect_language, is_browser_launch_line, is_fixture_definition_line, line_ignores_rule,
    scope_has_finally_browser_close, FileAliasMap, ARM_C_SHADOW_RULES,
};
#[doc(hidden)]
pub use scanner::{
    collect_files, collect_files_confined, parse_git_diff_lines, scan_git_staged_full,
    scan_git_staged_with_shadow, scan_path_full, scan_path_with_policy, scan_path_with_policy_sha,
    scan_path_with_policy_sha_and_shadow, scan_path_with_shadow, scan_text_buffer_bounded,
    scan_text_buffer_no_fs, scan_text_with_options, scan_text_with_policy, should_skip_dir,
    OptDynRules, MAX_DIFF_HUNK_LINES, MAX_REPO_FINDINGS, MAX_SOURCE_FILE_BYTES,
};
#[allow(deprecated)]
#[doc(hidden)]
pub use token_est::estimate_bpe_tokens;
#[doc(hidden)]
pub use token_est::{estimate_tokens, estimate_tokens_heuristic, HEURISTIC_CALIBRATION_MODEL};
#[doc(hidden)]
pub use unicode_policy::{
    contains_security_unicode_control, is_trojan_bidi_char, is_zero_width_smuggling_char,
    TROJAN_UTF8_SEQUENCES,
};
