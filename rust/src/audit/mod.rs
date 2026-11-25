//! Audit, PreToolUse JIT Gate, `@CT2` Seam Grading, Read-Only Memory Verifier & Step-Economics.

pub mod capsules;
pub mod context_envelope;
pub mod ct2_seams;
pub mod kmi_benchmark;
pub mod low_tier_lexicon;
pub mod memories;
pub mod obligation_prover;
pub mod pre_tool;
pub mod pre_tool_fields;
pub mod s3;
pub mod step_economics;

pub use capsules::{
    builtin_invariant_capsules, extract_code_capsule_signals, extract_symbol_blocks,
    load_custom_capsules_json, match_capsules_for_file, match_capsules_for_source,
    push_ident_subtokens, render_capsule_report_json, CapsuleMatchReport, InvariantCapsule,
    SymbolBlock,
};
pub use context_envelope::{
    build_context_envelope_for_file, build_context_envelope_for_source, evaluate_post_read_hook_json,
    render_context_envelope_json, ContextEnvelope, CONTEXT_ENVELOPE_SCHEMA,
    DEFAULT_ENVELOPE_MAX_TOKENS,
};
pub use ct2_seams::{
    classify_seam, classify_seams_for_file, classify_seams_in_line_masked, extract_identifiers,
    grade_transform_line, is_ct2_stopword, is_ct2_supported_ext, mask_strings_and_comments,
    strip_inline_comment, LexMode, StatefulMasker,
};
pub use low_tier_lexicon::{
    match_low_tier_lexicon_for_file, match_low_tier_lexicon_for_source, render_all_lexicon_json,
    render_lexicon_report_json, LexiconMatchReport, PitfallEntry, LOW_TIER_PITFALL_LEXICON,
};
pub use obligation_prover::{
    prove_file_obligations, Obligation, ObligationState, Span, OBLIGATION_PROVER_KIND,
};
pub use kmi_benchmark::{
    compute_token_benchmark, render_creed_json, render_kmi_compact_header, render_verbose_guardrail_manual,
};
pub use memories::{
    render_memories_verify_json, verify_memories_readonly, MemoriesVerifyReport,
    MEMORIES_ENFORCEMENT_MODE, MEMORIES_READ_ONLY_BEHAVIOR,
};
pub use pre_tool::{
    evaluate_pre_tool_detailed, evaluate_pre_tool_json, evaluate_pre_tool_json_with_workspace,
    infer_pretool_source_language, resolve_trusted_workspace_dir, HookEvaluation,
};
pub use pre_tool_fields::{
    classify_field_role, extract_pre_tool_fields, is_edit_or_patch_tool, is_shell_tool_name,
    looks_like_python_code, BomPolicy, ExtractedField, FieldRole, MAX_PRETOOL_DECODED_BYTES, MAX_PRETOOL_STRINGS,
};
pub use s3::{
    compute_s3_verdicts, render_s3_audit_json, s3_audit_file, s3_audit_file_with_mode, s3_audit_path,
    s3_audit_path_with_mode, FailingSeam, S3AuditSummary, S3FileAudit, SeamEvidence,
    S3_AUDITOR_KIND, S3_EVIDENCE_MODEL,
};
pub use step_economics::{
    audit_step_economics_files, audit_step_economics_path, render_step_audit_json, render_swarm_plan_json,
    AuditStepEconomicsWithFiles, StepAuditReport, MAX_TOTAL_TRANSCRIPT_BYTES, MAX_TRANSCRIPT_FILE_BYTES,
    MAX_TRANSCRIPT_LINE_BYTES, MAX_TRANSCRIPT_RECORDS,
};
#[allow(deprecated)]
pub use crate::token_est::{estimate_bpe_tokens, estimate_tokens, estimate_tokens_heuristic, HEURISTIC_CALIBRATION_MODEL};
