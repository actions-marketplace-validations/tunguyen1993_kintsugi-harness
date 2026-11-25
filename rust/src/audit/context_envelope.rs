//! Multi-Client `ContextEnvelope`, `PostToolUse(Read)` Hook & `task-pack` Engine (`rust/src/audit/context_envelope.rs`).
//!
//! Unifies pre-read JIT context delivery across Claude Code (`PostToolUse(Read)`), Antigravity (MCP),
//! ZCode `GLM-4-Flash`/`GLM-4-Flash` (`task-pack --low-tier` / MCP), and Cloud Sandbox (manual packet).
//!
//! Tracks exact snapshot binding (`source_digest`, `policy_digest`, `capsule_digest`, `cache_key`),
//! 3-stage receipt progression (`issued -> included_in_input -> patch_bound`), and strict token caps
//! (`<= 320` tokens per read by default).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::audit::capsules::{
    extract_symbol_blocks, match_capsules_for_source_excluding, InvariantCapsule, SymbolBlock,
};
use crate::audit::ct2_seams::StatefulMasker;
use crate::audit::delivery_telemetry::try_load_frozen_ids;
use crate::audit::low_tier_lexicon::match_low_tier_lexicon_for_source_excluding;
use crate::audit::obligation_prover::{prove_file_obligations, ObligationState};
use crate::io_json::{read_regular_file_fd_verified, JsonArr, JsonObj, ENGINE_VERSION};
use crate::json_dom::{parse_json_value, JsonValue};
use crate::policy::sha256_hex;
use crate::rules::detect_language;
use crate::scanner::MAX_SOURCE_FILE_BYTES;
use crate::token_est::estimate_tokens;

pub const DEFAULT_ENVELOPE_MAX_TOKENS: usize = 320;
pub const CONTEXT_ENVELOPE_SCHEMA: &str = "ContextEnvelope/3";

#[derive(Debug, Clone)]
pub struct ContextEnvelope {
    pub workspace_id: String,
    pub path: String,
    pub lang: String,
    pub source_digest: String,
    pub policy_digest: String,
    pub capsule_digest: String,
    pub cache_key: String,
    pub nonce: String,
    pub receipt_stage: &'static str,
    pub symbol_spans: Vec<SymbolBlock>,
    pub capsule_ids: Vec<String>,
    pub lexicon_ids: Vec<String>,
    pub obligations_proven: usize,
    pub obligations_violated: usize,
    pub obligations_unknown: usize,
    pub obligations_unsupported: usize,
    pub compact_context: String,
    pub estimated_tokens: usize,
    pub elapsed_us: u64,
}

pub fn clip_text_to_max_tokens(text: &str, max_tokens: usize) -> String {
    if max_tokens == 0 || text.is_empty() {
        return String::new();
    }
    if estimate_tokens(text) <= max_tokens {
        return text.to_string();
    }
    let boundaries: Vec<usize> = text
        .char_indices()
        .map(|(idx, _)| idx)
        .chain(std::iter::once(text.len()))
        .collect();
    let (mut lo, mut hi) = (0usize, boundaries.len().saturating_sub(1));
    while lo < hi {
        let mid = lo + (hi - lo + 1) / 2;
        if estimate_tokens(&text[..boundaries[mid]]) <= max_tokens {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    text[..boundaries[lo]].trim_end().to_string()
}

fn make_envelope_header(
    source_digest: &str,
    policy_digest: &str,
    capsule_ids: &[String],
    lexicon_ids: &[String],
) -> (String, String, String) {
    let cap_key_src = format!("{}|{}", capsule_ids.join(","), lexicon_ids.join(","));
    let capsule_digest = sha256_hex(cap_key_src.as_bytes())[..16].to_string();
    let cache_key = sha256_hex(format!("{source_digest}:{policy_digest}:{capsule_digest}").as_bytes())[..16].to_string();
    let hdr = format!(
        "@ENVELOPE[v3|sha={source_digest}|cache={cache_key}|stage=issued|caps={}|lex={}]",
        capsule_ids.len(),
        lexicon_ids.len()
    );
    (capsule_digest, cache_key, hdr)
}

fn assemble_envelope_text(hdr: &str, obs: &[String], caps: &[String], lexs: &[String]) -> String {
    let mut secs: Vec<String> = Vec::with_capacity(4);
    secs.push(hdr.to_string());
    if !obs.is_empty() {
        secs.push(obs.join("\n"));
    }
    if !caps.is_empty() {
        secs.push(caps.join("\n\n"));
    }
    if !lexs.is_empty() {
        secs.push(lexs.join("\n"));
    }
    secs.join("\n\n")
}

fn resolve_frozen_ids(
    workspace_hint: Option<&Path>,
    telemetry_store: Option<&Path>,
) -> Result<BTreeSet<String>, String> {
    if let Some(p) = telemetry_store {
        return try_load_frozen_ids(p);
    }
    let default_path = match workspace_hint {
        Some(ws) => ws.join(".kintsugi").join("delivery_telemetry.json"),
        None => PathBuf::from(".kintsugi/delivery_telemetry.json"),
    };
    match std::fs::symlink_metadata(&default_path) {
        Ok(_) => try_load_frozen_ids(&default_path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeSet::new()),
        Err(e) => Err(format!("TELEMETRY_STAT_ERROR: {e}")),
    }
}

pub fn build_context_envelope_for_source_with_frozen(
    path: &Path,
    content: &str,
    workspace_hint: Option<&Path>,
    extra_capsules: &[InvariantCapsule],
    include_low_tier_lexicon: bool,
    max_tokens: usize,
    frozen_ids: &BTreeSet<String>,
) -> ContextEnvelope {
    let t0 = Instant::now();
    let lang = detect_language(path).unwrap_or("other").to_string();
    let source_digest = sha256_hex(content.as_bytes())[..16].to_string();
    let ws_label = workspace_hint
        .map(|p| p.to_string_lossy().to_string())
        .or_else(|| path.parent().map(|p| p.to_string_lossy().to_string()))
        .unwrap_or_else(|| ".".to_string());
    let workspace_id = sha256_hex(ws_label.as_bytes())[..12].to_string();

    let symbol_spans = extract_symbol_blocks(content);
    let cap_rep = match_capsules_for_source_excluding(
        &path.to_string_lossy(),
        content,
        extra_capsules,
        frozen_ids,
        4,
    );
    let lex_rep = if include_low_tier_lexicon {
        Some(match_low_tier_lexicon_for_source_excluding(
            &path.to_string_lossy(),
            content,
            &lang,
            frozen_ids,
            4,
        ))
    } else {
        None
    };

    let masked = StatefulMasker::mask_file_lines(content);
    let obs = prove_file_obligations(path, content, &masked);
    let (mut proven, mut violated, mut unknown, mut unsupported) = (0usize, 0usize, 0usize, 0usize);
    let mut ob_warnings = Vec::new();
    for o in &obs {
        match o.state {
            ObligationState::Proven => proven += 1,
            ObligationState::Violated => {
                violated += 1;
                ob_warnings.push(format!(
                    "@OBLIGATION[VIOLATED|{}|L{}] {} | Fix: {}",
                    o.rule, o.sink_span.start_line, o.reason, o.fix_hint
                ));
            }
            ObligationState::Unknown => {
                unknown += 1;
                ob_warnings.push(format!(
                    "@OBLIGATION[UNKNOWN|{}|L{}] {} | Fix: {}",
                    o.rule, o.sink_span.start_line, o.reason, o.fix_hint
                ));
            }
            ObligationState::Unsupported => unsupported += 1,
        }
    }

    let policy_digest = sha256_hex(format!("{ENGINE_VERSION}:{CONTEXT_ENVELOPE_SCHEMA}:low_tier={include_low_tier_lexicon}").as_bytes())[..16].to_string();
    let has_candidates = !ob_warnings.is_empty()
        || !cap_rep.matched_capsules.is_empty()
        || lex_rep.as_ref().map_or(false, |r| !r.matched_entries.is_empty());

    let mut capsule_ids: Vec<String> = Vec::new();
    let mut lexicon_ids: Vec<String> = Vec::new();
    let (capsule_digest, cache_key, compact_context) = if !has_candidates {
        let (cd, ck, _) = make_envelope_header(&source_digest, &policy_digest, &capsule_ids, &lexicon_ids);
        (cd, ck, String::new())
    } else {
        let mut inc_obs: Vec<String> = Vec::new();
        let mut inc_cap_texts: Vec<String> = Vec::new();
        let mut inc_lex_texts: Vec<String> = Vec::new();

        let try_add_lex = |entry: &crate::audit::low_tier_lexicon::PitfallEntry,
                               capsule_ids: &[String],
                               lexicon_ids: &mut Vec<String>,
                               inc_obs: &[String],
                               inc_cap_texts: &[String],
                               inc_lex_texts: &mut Vec<String>| {
            let mut next_ids = lexicon_ids.clone();
            next_ids.push(entry.id.to_string());
            let mut next_texts = inc_lex_texts.clone();
            next_texts.push(entry.render_compact());
            let (_, _, hdr) = make_envelope_header(&source_digest, &policy_digest, capsule_ids, &next_ids);
            let cand = assemble_envelope_text(&hdr, inc_obs, inc_cap_texts, &next_texts);
            if estimate_tokens(&cand) <= max_tokens {
                *lexicon_ids = next_ids;
                *inc_lex_texts = next_texts;
            }
        };

        for ob in &ob_warnings {
            let mut next_obs = inc_obs.clone();
            next_obs.push(ob.clone());
            let (_, _, hdr) = make_envelope_header(&source_digest, &policy_digest, &capsule_ids, &lexicon_ids);
            let cand = assemble_envelope_text(&hdr, &next_obs, &inc_cap_texts, &inc_lex_texts);
            if estimate_tokens(&cand) <= max_tokens {
                inc_obs = next_obs;
            }
        }
        // When --low-tier is enabled, reserve slot for the top-ranked pitfall before bulky capsules
        // so a single ~200-token capsule cannot starve the low-tier lexicon under the 320-token cap.
        let mut lex_start = 0usize;
        if let Some(lr) = &lex_rep {
            if let Some(first_entry) = lr.matched_entries.first() {
                try_add_lex(
                    first_entry,
                    &capsule_ids,
                    &mut lexicon_ids,
                    &inc_obs,
                    &inc_cap_texts,
                    &mut inc_lex_texts,
                );
                lex_start = 1;
            }
        }
        for cap in &cap_rep.matched_capsules {
            let mut next_ids = capsule_ids.clone();
            next_ids.push(cap.id.clone());
            let mut next_texts = inc_cap_texts.clone();
            next_texts.push(cap.render_compact());
            let (_, _, hdr) = make_envelope_header(&source_digest, &policy_digest, &next_ids, &lexicon_ids);
            let cand = assemble_envelope_text(&hdr, &inc_obs, &next_texts, &inc_lex_texts);
            if estimate_tokens(&cand) <= max_tokens {
                capsule_ids = next_ids;
                inc_cap_texts = next_texts;
            }
        }
        if let Some(lr) = &lex_rep {
            for entry in lr.matched_entries.iter().skip(lex_start) {
                try_add_lex(
                    entry,
                    &capsule_ids,
                    &mut lexicon_ids,
                    &inc_obs,
                    &inc_cap_texts,
                    &mut inc_lex_texts,
                );
            }
        }

        let (cd, ck, hdr) = make_envelope_header(&source_digest, &policy_digest, &capsule_ids, &lexicon_ids);
        let text = if inc_obs.is_empty() && inc_cap_texts.is_empty() && inc_lex_texts.is_empty() {
            clip_text_to_max_tokens(&hdr, max_tokens)
        } else {
            assemble_envelope_text(&hdr, &inc_obs, &inc_cap_texts, &inc_lex_texts)
        };
        (cd, ck, text)
    };

    let now_ns = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let nonce = sha256_hex(format!("{cache_key}:{now_ns}").as_bytes())[..12].to_string();
    let estimated_tokens = if compact_context.is_empty() { 0 } else { estimate_tokens(&compact_context) };

    ContextEnvelope {
        workspace_id,
        path: path.to_string_lossy().to_string(),
        lang,
        source_digest,
        policy_digest,
        capsule_digest,
        cache_key,
        nonce,
        receipt_stage: "issued",
        symbol_spans,
        capsule_ids,
        lexicon_ids,
        obligations_proven: proven,
        obligations_violated: violated,
        obligations_unknown: unknown,
        obligations_unsupported: unsupported,
        compact_context,
        estimated_tokens,
        elapsed_us: t0.elapsed().as_micros() as u64,
    }
}

pub fn build_context_envelope_for_source(
    path: &Path,
    content: &str,
    workspace_hint: Option<&Path>,
    extra_capsules: &[InvariantCapsule],
    include_low_tier_lexicon: bool,
    max_tokens: usize,
) -> ContextEnvelope {
    build_context_envelope_for_source_with_frozen(
        path,
        content,
        workspace_hint,
        extra_capsules,
        include_low_tier_lexicon,
        max_tokens,
        &BTreeSet::new(),
    )
}

pub fn build_context_envelope_for_file(
    path: &Path,
    workspace_hint: Option<&Path>,
    extra_capsules: &[InvariantCapsule],
    include_low_tier_lexicon: bool,
    max_tokens: usize,
) -> Result<ContextEnvelope, String> {
    let content = read_regular_file_fd_verified(path, MAX_SOURCE_FILE_BYTES)?;
    Ok(build_context_envelope_for_source(
        path,
        &content,
        workspace_hint,
        extra_capsules,
        include_low_tier_lexicon,
        max_tokens,
    ))
}

pub fn build_context_envelope_for_file_with_telemetry(
    path: &Path,
    workspace_hint: Option<&Path>,
    extra_capsules: &[InvariantCapsule],
    include_low_tier_lexicon: bool,
    max_tokens: usize,
    telemetry_store: Option<&Path>,
) -> Result<ContextEnvelope, String> {
    let frozen_ids = resolve_frozen_ids(workspace_hint, telemetry_store)?;
    let content = read_regular_file_fd_verified(path, MAX_SOURCE_FILE_BYTES)?;
    Ok(build_context_envelope_for_source_with_frozen(
        path,
        &content,
        workspace_hint,
        extra_capsules,
        include_low_tier_lexicon,
        max_tokens,
        &frozen_ids,
    ))
}

pub fn render_context_envelope_json(env: &ContextEnvelope) -> String {
    let mut syms = JsonArr::new();
    for s in env.symbol_spans.iter().take(32) {
        syms = syms.obj(
            JsonObj::new()
                .str("name", &s.name)
                .usize("start_line", s.start_line)
                .usize("end_line", s.end_line),
        );
    }
    let mut caps = JsonArr::new();
    for id in &env.capsule_ids {
        caps = caps.str(id);
    }
    let mut lexs = JsonArr::new();
    for id in &env.lexicon_ids {
        lexs = lexs.str(id);
    }
    let ob_summary = JsonObj::new()
        .usize("proven", env.obligations_proven)
        .usize("violated", env.obligations_violated)
        .usize("unknown", env.obligations_unknown)
        .usize("unsupported", env.obligations_unsupported)
        .finish();

    JsonObj::with_capacity(env.compact_context.len() + 512)
        .bool("ok", true)
        .str("schema", CONTEXT_ENVELOPE_SCHEMA)
        .str("schema_version", ENGINE_VERSION)
        .str("workspace_id", &env.workspace_id)
        .str("path", &env.path)
        .str("lang", &env.lang)
        .str("source_digest", &env.source_digest)
        .str("policy_digest", &env.policy_digest)
        .str("capsule_digest", &env.capsule_digest)
        .str("cache_key", &env.cache_key)
        .str("nonce", &env.nonce)
        .str("receipt_stage", env.receipt_stage)
        .arr("symbol_spans", syms)
        .arr("capsule_ids", caps)
        .arr("lexicon_ids", lexs)
        .raw("obligations", &ob_summary)
        .usize("estimated_tokens", env.estimated_tokens)
        .u64("elapsed_us", env.elapsed_us)
        .f64_3("elapsed_ms", (env.elapsed_us as f64) / 1000.0)
        .str("context", &env.compact_context)
        .finish()
}

#[derive(Debug, Clone)]
pub struct TaskPackResult {
    pub files: Vec<ContextEnvelope>,
    pub packet: String,
    pub total_tokens: usize,
}

/// Build a strictly token-capped multi-file `task-pack` packet where
/// `total_tokens == estimate_tokens(&packet) <= max_tokens` ALWAYS holds,
/// accounting for `### FILE: ...` headers and `\n\n` separators, and returning ONLY
/// files actually included in `packet` with honest `capsule_ids` and `lexicon_ids`.
pub fn build_task_pack_with_telemetry(
    targets: &[&Path],
    include_low_tier: bool,
    max_tokens: usize,
    telemetry_store: Option<&Path>,
) -> Result<TaskPackResult, String> {
    let frozen_ids = resolve_frozen_ids(None, telemetry_store)?;
    let mut loaded: Vec<(&Path, String, String)> = Vec::with_capacity(targets.len());
    for &p in targets {
        let content = read_regular_file_fd_verified(p, MAX_SOURCE_FILE_BYTES)?;
        let digest = sha256_hex(content.as_bytes())[..16].to_string();
        let header = format!("### FILE: {} (sha={digest})\n", p.to_string_lossy());
        loaded.push((p, content, header));
    }

    let mut included_files: Vec<ContextEnvelope> = Vec::new();
    let mut combined = String::new();
    let mut combined_tokens = 0usize;
    let single_target = loaded.len() == 1;

    for (idx, (path, content, header)) in loaded.iter().enumerate() {
        let remaining_files = loaded.len() - idx;
        let sep = if combined.is_empty() { "" } else { "\n\n" };
        let header_probe = format!("{combined}{sep}{header}");
        let header_probe_tokens = estimate_tokens(&header_probe);

        if header_probe_tokens > max_tokens {
            if single_target {
                let probe = build_context_envelope_for_source_with_frozen(
                    path,
                    content,
                    None,
                    &[],
                    include_low_tier,
                    max_tokens,
                    &frozen_ids,
                );
                if probe.compact_context.is_empty() {
                    continue;
                }
                let assembled = format!("{header}{}", probe.compact_context);
                let clipped = clip_text_to_max_tokens(&assembled, max_tokens);
                if !clipped.is_empty() {
                    let mut env = probe;
                    env.capsule_ids.clear();
                    env.lexicon_ids.clear();
                    let (cd, ck, _) = make_envelope_header(
                        &env.source_digest,
                        &env.policy_digest,
                        &env.capsule_ids,
                        &env.lexicon_ids,
                    );
                    env.capsule_digest = cd;
                    env.cache_key = ck;
                    env.compact_context = clipped.strip_prefix(header.as_str()).unwrap_or("").to_string();
                    let tok = estimate_tokens(&clipped);
                    env.estimated_tokens = tok;
                    combined = clipped;
                    combined_tokens = tok;
                    included_files.push(env);
                }
            }
            continue;
        }

        let header_only_tokens = estimate_tokens(header);
        let sep_tokens = if combined.is_empty() { 0 } else { 1 };
        let usable_remaining = max_tokens.saturating_sub(combined_tokens).saturating_sub(sep_tokens);
        let max_body_budget = max_tokens.saturating_sub(header_probe_tokens);
        let mut env_budget = if single_target {
            max_body_budget
        } else {
            let min_per_file = header_only_tokens.saturating_add(1).max(1);
            let est_fittable = (usable_remaining / min_per_file).clamp(1, remaining_files);
            let fair_file_budget = usable_remaining / est_fittable;
            fair_file_budget.saturating_sub(header_only_tokens).min(max_body_budget)
        };

        if env_budget == 0 {
            if single_target {
                let probe = build_context_envelope_for_source_with_frozen(
                    path,
                    content,
                    None,
                    &[],
                    include_low_tier,
                    1,
                    &frozen_ids,
                );
                if !probe.compact_context.is_empty() {
                    let block = header.trim_end().to_string();
                    let tok = estimate_tokens(&block);
                    if tok <= max_tokens {
                        let mut env = probe;
                        env.capsule_ids.clear();
                        env.lexicon_ids.clear();
                        let (cd, ck, _) = make_envelope_header(
                            &env.source_digest,
                            &env.policy_digest,
                            &env.capsule_ids,
                            &env.lexicon_ids,
                        );
                        env.capsule_digest = cd;
                        env.cache_key = ck;
                        env.compact_context.clear();
                        env.estimated_tokens = tok;
                        combined = block;
                        combined_tokens = tok;
                        included_files.push(env);
                    }
                }
            }
            continue;
        }

        let mut chosen: Option<(ContextEnvelope, String, usize)> = None;
        loop {
            let mut env = build_context_envelope_for_source_with_frozen(
                path,
                content,
                None,
                &[],
                include_low_tier,
                env_budget,
                &frozen_ids,
            );
            if env.compact_context.is_empty() {
                break;
            }
            let block = format!("{header}{}", env.compact_context);
            let cand_combined = if combined.is_empty() {
                block.clone()
            } else {
                format!("{combined}\n\n{block}")
            };
            let cand_tokens = estimate_tokens(&cand_combined);
            if cand_tokens <= max_tokens {
                env.estimated_tokens = estimate_tokens(&block);
                chosen = Some((env, cand_combined, cand_tokens));
                break;
            }
            let excess = cand_tokens - max_tokens;
            let next_budget = env_budget.saturating_sub(excess.max(1));
            if next_budget == 0 || next_budget == env_budget {
                break;
            }
            env_budget = next_budget;
        }
        if let Some((env, next_combined, next_tokens)) = chosen {
            combined = next_combined;
            combined_tokens = next_tokens;
            included_files.push(env);
        }
    }

    let total_tokens = if combined.is_empty() { 0 } else { estimate_tokens(&combined) };
    debug_assert!(total_tokens <= max_tokens);
    Ok(TaskPackResult {
        files: included_files,
        packet: combined,
        total_tokens,
    })
}

fn evaluate_post_read_hook_with_frozen(
    raw_stdin: &str,
    include_low_tier_lexicon: bool,
    max_tokens: usize,
    workspace_hint: Option<&Path>,
    frozen_ids: &BTreeSet<String>,
) -> String {
    let trimmed = raw_stdin.trim();
    let Ok(JsonValue::Object(root)) = parse_json_value(trimmed) else {
        let inner = JsonObj::new().str("hookEventName", "PostToolUse").finish();
        return JsonObj::new().raw("hookSpecificOutput", &inner).finish();
    };
    let tool_name = root.get("tool_name").or_else(|| root.get("tool")).and_then(|v| v.as_str()).unwrap_or("");
    let ti = root.get("tool_input").or_else(|| root.get("toolCall")).and_then(|v| v.as_object());
    let file_path = ti
        .and_then(|o| o.get("file_path").or_else(|| o.get("path")).or_else(|| o.get("Path")))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .unwrap_or("");

    if !matches!(tool_name, "Read" | "read_file" | "view_file" | "") || file_path.is_empty() {
        let inner = JsonObj::new().str("hookEventName", "PostToolUse").finish();
        return JsonObj::new().raw("hookSpecificOutput", &inner).finish();
    }

    let raw_path = Path::new(file_path);
    let resolved_path: PathBuf = if raw_path.is_relative() {
        if let Some(ws) = workspace_hint {
            ws.join(raw_path)
        } else {
            raw_path.to_path_buf()
        }
    } else {
        raw_path.to_path_buf()
    };

    match read_regular_file_fd_verified(&resolved_path, MAX_SOURCE_FILE_BYTES) {
        Ok(content) => {
            let env = build_context_envelope_for_source_with_frozen(
                &resolved_path,
                &content,
                workspace_hint,
                &[],
                include_low_tier_lexicon,
                max_tokens,
                frozen_ids,
            );
            let mut inner = JsonObj::with_capacity(env.compact_context.len() + 96)
                .str("hookEventName", "PostToolUse");
            if !env.compact_context.is_empty() {
                inner = inner.str("additionalContext", &env.compact_context);
            }
            let inner_s = inner.finish();
            let env_s = render_context_envelope_json(&env);
            JsonObj::with_capacity(inner_s.len() + env_s.len() + 64)
                .raw("hookSpecificOutput", &inner_s)
                .raw("kintsugiEnvelope", &env_s)
                .finish()
        }
        Err(_) => {
            let inner = JsonObj::new().str("hookEventName", "PostToolUse").finish();
            JsonObj::new().raw("hookSpecificOutput", &inner).finish()
        }
    }
}

/// Evaluate a Claude Code `PostToolUse` hook stdin JSON payload for `Read` tool calls, returning
/// `hookSpecificOutput.additionalContext` bound to the exact `source_digest` snapshot.
pub fn evaluate_post_read_hook_json(
    raw_stdin: &str,
    include_low_tier_lexicon: bool,
    max_tokens: usize,
) -> String {
    evaluate_post_read_hook_with_frozen(raw_stdin, include_low_tier_lexicon, max_tokens, None, &BTreeSet::new())
}

/// Evaluate a Claude Code `PostToolUse` hook payload with fail-closed telemetry auto-freeze filtering.
pub fn evaluate_post_read_hook_json_with_telemetry(
    raw_stdin: &str,
    include_low_tier_lexicon: bool,
    max_tokens: usize,
    telemetry_store: Option<&Path>,
) -> Result<String, String> {
    evaluate_post_read_hook_json_with_workspace_telemetry(
        raw_stdin,
        include_low_tier_lexicon,
        max_tokens,
        None,
        telemetry_store,
    )
}

/// Evaluate a Claude Code `PostToolUse` hook payload with workspace-aware fail-closed telemetry filtering.
pub fn evaluate_post_read_hook_json_with_workspace_telemetry(
    raw_stdin: &str,
    include_low_tier_lexicon: bool,
    max_tokens: usize,
    workspace: Option<&Path>,
    telemetry_store: Option<&Path>,
) -> Result<String, String> {
    let frozen_ids = resolve_frozen_ids(workspace, telemetry_store)?;
    Ok(evaluate_post_read_hook_with_frozen(
        raw_stdin,
        include_low_tier_lexicon,
        max_tokens,
        workspace,
        &frozen_ids,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use crate::audit::delivery_telemetry::record_telemetry_event;

    #[test]
    fn context_envelope_binds_source_digest_caps_tokens_and_emits_post_read_hook() {
        let uniq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let f = std::env::temp_dir().join(format!("kintsugi_env_{}_{uniq}.py", std::process::id()));
        fs::write(
            &f,
            "import subprocess\ndef query_and_run(cur, uid, bin_path):\n    sql = 'SELECT * FROM orders WHERE id = ?'\n    cur.execute(sql, (uid,))\n    subprocess.run([bin_path, '--check'], shell=False)\n",
        )
        .unwrap();

        let env = build_context_envelope_for_file(&f, None, &[], true, 320).unwrap();
        assert_eq!(env.receipt_stage, "issued");
        assert_eq!(env.obligations_proven, 2);
        assert_eq!(env.obligations_violated, 0);
        assert!(env.estimated_tokens <= 320);
        assert!(env.lexicon_ids.iter().any(|id| id == "LT-003" || id == "LT-005"));
        assert!(parse_json_value(&render_context_envelope_json(&env)).is_ok());

        let hook_in = JsonObj::new()
            .str("tool_name", "Read")
            .raw("tool_input", &JsonObj::new().str("file_path", &f.to_string_lossy()).finish())
            .finish();
        let hook_out = evaluate_post_read_hook_json(&hook_in, true, 320);
        assert!(parse_json_value(&hook_out).is_ok());
        assert!(hook_out.contains("\"hookEventName\":\"PostToolUse\""));
        assert!(hook_out.contains(&env.source_digest));
        let _ = fs::remove_file(&f);
    }

    #[test]
    fn strict_max_tokens_budget_and_honest_included_ids() {
        let code = "import subprocess\ndef query_and_run(cur, uid, bin_path):\n    sql = 'SELECT * FROM orders WHERE id = ?'\n    cur.execute(sql, (uid,))\n    subprocess.run([bin_path, '--check'], shell=False)\n";
        for cap in [16usize, 32, 95, 160, 320] {
            let env = build_context_envelope_for_source(Path::new("sample.py"), code, None, &[], true, cap);
            assert!(
                env.estimated_tokens <= cap,
                "max_tokens={cap} exceeded: got {} tokens for {:?}",
                env.estimated_tokens,
                env.compact_context
            );
            for cid in &env.capsule_ids {
                assert!(
                    env.compact_context.contains(cid),
                    "capsule_id {cid} absent from compact_context under max_tokens={cap}"
                );
            }
            for lid in &env.lexicon_ids {
                assert!(
                    env.compact_context.contains(lid),
                    "lexicon_id {lid} absent from compact_context under max_tokens={cap}"
                );
            }
        }
        // Under max_tokens=32, no multi-line pitfall/capsule fits so IDs must be honest empty
        let tight = build_context_envelope_for_source(Path::new("sample.py"), code, None, &[], true, 32);
        assert!(tight.estimated_tokens <= 32);
        assert!(tight.capsule_ids.is_empty() && tight.lexicon_ids.is_empty());
    }

    #[test]
    fn telemetry_frozen_ids_wired_into_envelope_and_hook_fail_closed() {
        let uniq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("kintsugi_env_tel_{}_{uniq}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let sample = dir.join("sample.py");
        fs::write(
            &sample,
            "import subprocess\ndef query_and_run(cur, uid, bin_path):\n    sql = 'SELECT * FROM orders WHERE id = ?'\n    cur.execute(sql, (uid,))\n    subprocess.run([bin_path, '--check'], shell=False)\n",
        )
        .unwrap();
        let store = dir.join("delivery_telemetry.json");
        let caps = vec!["CAP-SEC-SUBPROCESS-ARGV".to_string()];
        let pits = vec!["LT-003".to_string()];
        for (s, e, p) in [("s1", "e1", "p1"), ("s2", "e2", "p2")] {
            record_telemetry_event(&store, "claude_code", "issued", s, e, "d1", "", &caps, &pits, 90, None).unwrap();
            record_telemetry_event(&store, "claude_code", "included_in_input", s, e, "", "", &[], &[], 0, None).unwrap();
            record_telemetry_event(&store, "claude_code", "patch_bound", s, e, "", p, &[], &[], 0, Some(false)).unwrap();
        }
        let baseline = build_context_envelope_for_file(&sample, None, &[], true, 640).unwrap();
        assert!(baseline.capsule_ids.iter().any(|id| id == "CAP-SEC-SUBPROCESS-ARGV"));
        assert!(baseline.lexicon_ids.iter().any(|id| id == "LT-003"));

        let filtered = build_context_envelope_for_file_with_telemetry(&sample, None, &[], true, 640, Some(&store)).unwrap();
        assert!(!filtered.capsule_ids.iter().any(|id| id == "CAP-SEC-SUBPROCESS-ARGV"));
        assert!(!filtered.lexicon_ids.iter().any(|id| id == "LT-003"));
        assert!(!filtered.compact_context.contains("CAP-SEC-SUBPROCESS-ARGV"));
        assert!(!filtered.compact_context.contains("LT-003"));

        let hook_in = JsonObj::new()
            .str("tool_name", "Read")
            .raw("tool_input", &JsonObj::new().str("file_path", &sample.to_string_lossy()).finish())
            .finish();
        let hook_out = evaluate_post_read_hook_json_with_telemetry(&hook_in, true, 640, Some(&store)).unwrap();
        assert!(!hook_out.contains("CAP-SEC-SUBPROCESS-ARGV"));
        assert!(!hook_out.contains("LT-003"));

        let corrupt = dir.join("corrupt.json");
        fs::write(&corrupt, r#"{"note":1}"#).unwrap();
        assert!(build_context_envelope_for_file_with_telemetry(&sample, None, &[], true, 640, Some(&corrupt)).is_err());
        assert!(evaluate_post_read_hook_json_with_telemetry(&hook_in, true, 640, Some(&corrupt)).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn post_read_hook_discovers_workspace_telemetry_store_when_store_arg_omitted() {
        let uniq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let ws = std::env::temp_dir().join(format!("kintsugi_ws_hook_{}_{uniq}", std::process::id()));
        fs::create_dir_all(ws.join(".kintsugi")).unwrap();
        let sample = ws.join("sample.py");
        fs::write(
            &sample,
            "import subprocess\ndef query_and_run(cur, uid, bin_path):\n    sql = 'SELECT * FROM orders WHERE id = ?'\n    cur.execute(sql, (uid,))\n    subprocess.run([bin_path, '--check'], shell=False)\n",
        )
        .unwrap();
        let store = ws.join(".kintsugi").join("delivery_telemetry.json");
        let caps = vec!["CAP-SEC-SUBPROCESS-ARGV".to_string()];
        let pits = vec!["LT-003".to_string()];
        for (s, e, p) in [("s1", "e1", "p1"), ("s2", "e2", "p2")] {
            record_telemetry_event(&store, "claude_code", "issued", s, e, "d1", "", &caps, &pits, 90, None).unwrap();
            record_telemetry_event(&store, "claude_code", "included_in_input", s, e, "", "", &[], &[], 0, None).unwrap();
            record_telemetry_event(&store, "claude_code", "patch_bound", s, e, "", p, &[], &[], 0, Some(false)).unwrap();
        }
        let hook_in = JsonObj::new()
            .str("tool_name", "Read")
            .raw("tool_input", &JsonObj::new().str("file_path", &sample.to_string_lossy()).finish())
            .finish();
        let out = evaluate_post_read_hook_json_with_workspace_telemetry(&hook_in, true, 640, Some(&ws), None).unwrap();
        assert!(!out.contains("CAP-SEC-SUBPROCESS-ARGV"), "expected workspace telemetry to freeze CAP-SEC-SUBPROCESS-ARGV: {out}");
        assert!(!out.contains("LT-003"), "expected workspace telemetry to freeze LT-003: {out}");
        let _ = fs::remove_dir_all(&ws);
    }

    #[test]
    fn task_pack_enforces_strict_max_tokens_single_and_multi_file() {
        let uniq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("kintsugi_tp_{}_{uniq}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let code = "import subprocess\ndef query_and_run(cur, uid, bin_path):\n    sql = 'SELECT * FROM orders WHERE id = ?'\n    cur.execute(sql, (uid,))\n    subprocess.run([bin_path, '--check'], shell=False)\n";
        let mut paths = Vec::new();
        for i in 0..10 {
            let p = dir.join(format!("mod_{i}.py"));
            fs::write(&p, code).unwrap();
            paths.push(p);
        }
        let one: [&Path; 1] = [paths[0].as_path()];
        for cap in [8usize, 32, 96, 320] {
            let pack = build_task_pack_with_telemetry(&one, true, cap, None).unwrap();
            assert_eq!(pack.total_tokens, estimate_tokens(&pack.packet));
            assert!(pack.total_tokens <= cap, "single-file cap={cap} violated: got {}", pack.total_tokens);
            for env in &pack.files {
                for cid in &env.capsule_ids {
                    assert!(pack.packet.contains(cid), "capsule {cid} missing from packet under cap={cap}");
                }
                for lid in &env.lexicon_ids {
                    assert!(pack.packet.contains(lid), "lexicon {lid} missing from packet under cap={cap}");
                }
            }
        }
        let many: Vec<&Path> = paths.iter().map(PathBuf::as_path).collect();
        let pack_many = build_task_pack_with_telemetry(&many, true, 200, None).unwrap();
        assert_eq!(pack_many.total_tokens, estimate_tokens(&pack_many.packet));
        assert!(pack_many.total_tokens <= 200, "multi-file cap=200 violated: got {}", pack_many.total_tokens);
        for env in &pack_many.files {
            assert!(pack_many.packet.contains(&env.path));
            for cid in &env.capsule_ids {
                assert!(pack_many.packet.contains(cid));
            }
            for lid in &env.lexicon_ids {
                assert!(pack_many.packet.contains(lid));
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
