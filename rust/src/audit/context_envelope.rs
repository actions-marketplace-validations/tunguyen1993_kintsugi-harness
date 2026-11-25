//! Multi-Client `ContextEnvelope`, `PostToolUse(Read)` Hook & `task-pack` Engine (`rust/src/audit/context_envelope.rs`).
//!
//! Unifies pre-read JIT context delivery across Claude Code (`PostToolUse(Read)`), Antigravity (MCP),
//! ZCode `GLM-4-Flash`/`GLM-4-Flash` (`task-pack --low-tier` / MCP), and Cloud Sandbox (manual packet).
//!
//! Tracks exact snapshot binding (`source_digest`, `policy_digest`, `capsule_digest`, `cache_key`),
//! 3-stage receipt progression (`issued -> included_in_input -> patch_bound`), and strict token caps
//! (`<= 320` tokens per read by default).

use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::audit::capsules::{
    extract_symbol_blocks, match_capsules_for_source, InvariantCapsule, SymbolBlock,
};
use crate::audit::ct2_seams::StatefulMasker;
use crate::audit::low_tier_lexicon::match_low_tier_lexicon_for_source;
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

fn truncate_to_token_budget(sections: &[String], max_tokens: usize) -> String {
    let mut out = String::new();
    for sec in sections {
        let s = sec.trim();
        if s.is_empty() {
            continue;
        }
        let cand = if out.is_empty() { s.to_string() } else { format!("{out}\n\n{s}") };
        if estimate_tokens(&cand) <= max_tokens || out.is_empty() {
            out = cand;
        } else {
            // Fit as many lines from this section as budget permits
            for line in s.lines() {
                let next = if out.is_empty() { line.to_string() } else { format!("{out}\n{line}") };
                if estimate_tokens(&next) > max_tokens {
                    break;
                }
                out = next;
            }
            break;
        }
    }
    if estimate_tokens(&out) > max_tokens && max_tokens > 8 {
        let char_cap = max_tokens.saturating_mul(4);
        let mut clipped = String::new();
        for ch in out.chars() {
            if clipped.len() + ch.len_utf8() > char_cap {
                break;
            }
            clipped.push(ch);
        }
        return clipped;
    }
    out
}

pub fn build_context_envelope_for_source(
    path: &Path,
    content: &str,
    workspace_hint: Option<&Path>,
    extra_capsules: &[InvariantCapsule],
    include_low_tier_lexicon: bool,
    max_tokens: usize,
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
    let cap_rep = match_capsules_for_source(&path.to_string_lossy(), content, extra_capsules, 4);
    let lex_rep = if include_low_tier_lexicon {
        Some(match_low_tier_lexicon_for_source(&path.to_string_lossy(), content, &lang, 4))
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

    let capsule_ids: Vec<String> = cap_rep.matched_capsules.iter().map(|c| c.id.clone()).collect();
    let lexicon_ids: Vec<String> = lex_rep
        .as_ref()
        .map(|r| r.matched_entries.iter().map(|e| e.id.to_string()).collect())
        .unwrap_or_default();

    let policy_digest = sha256_hex(format!("{ENGINE_VERSION}:{CONTEXT_ENVELOPE_SCHEMA}:low_tier={include_low_tier_lexicon}").as_bytes())[..16].to_string();
    let cap_key_src = format!("{}|{}", capsule_ids.join(","), lexicon_ids.join(","));
    let capsule_digest = sha256_hex(cap_key_src.as_bytes())[..16].to_string();
    let cache_key = sha256_hex(format!("{source_digest}:{policy_digest}:{capsule_digest}").as_bytes())[..16].to_string();
    let now_ns = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let nonce = sha256_hex(format!("{cache_key}:{now_ns}").as_bytes())[..12].to_string();

    let mut sections: Vec<String> = Vec::new();
    if !ob_warnings.is_empty() {
        sections.push(ob_warnings.join("\n"));
    }
    if !cap_rep.compact_text.is_empty() {
        sections.push(cap_rep.compact_text);
    }
    if let Some(lr) = &lex_rep {
        if !lr.compact_text.is_empty() {
            sections.push(lr.compact_text.clone());
        }
    }
    let compact_context = if sections.is_empty() {
        String::new()
    } else {
        let hdr = format!(
            "@ENVELOPE[v3|sha={source_digest}|cache={cache_key}|stage=issued|caps={}|lex={}]",
            capsule_ids.len(),
            lexicon_ids.len()
        );
        let mut all_secs = vec![hdr];
        all_secs.extend(sections);
        truncate_to_token_budget(&all_secs, max_tokens.max(32))
    };
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

/// Evaluate a Claude Code `PostToolUse` hook stdin JSON payload for `Read` tool calls, returning
/// `hookSpecificOutput.additionalContext` bound to the exact `source_digest` snapshot.
pub fn evaluate_post_read_hook_json(
    raw_stdin: &str,
    include_low_tier_lexicon: bool,
    max_tokens: usize,
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

    match build_context_envelope_for_file(Path::new(file_path), None, &[], include_low_tier_lexicon, max_tokens) {
        Ok(env) => {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
}
