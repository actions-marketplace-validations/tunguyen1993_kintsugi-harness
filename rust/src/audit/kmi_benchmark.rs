//! `@KMI/1` Micro-Index Wire Header, Deterministic Subword Token Benchmark, and `@CREED/1` JSON (`audit/kmi_benchmark.rs`).

use std::collections::BTreeMap;
use std::fmt::Write as FmtWrite;

use crate::io_json::{JsonArr, JsonObj};
use crate::model::TokenBenchmark;
use crate::rules::BUILTIN_RULES;
use crate::token_est::{estimate_tokens_heuristic, HEURISTIC_CALIBRATION_MODEL};

/// Render the compact `@KMI/1` wire guardrail header with honest `subword_heuristic_v2` provenance.
pub fn render_kmi_compact_header() -> String {
    let mut by_tier: BTreeMap<u8, Vec<&'static str>> = BTreeMap::new();
    for rule in BUILTIN_RULES {
        by_tier.entry(rule.severity as u8).or_default().push(rule.kmi_token);
    }
    let mut out = format!(
        "<!-- KINTSUGI:KMI/1 START -->\n# KINTSUGI-KMI/1 (Ultra-Low-Token Wire Index | JIT PreToolUse Active | estimator=subword_heuristic_v2 | \"estimator_model\":\"{HEURISTIC_CALIBRATION_MODEL}\")\n",
    );
    for (rank, label) in [(4u8, "@CRIT"), (3u8, "@HIGH"), (2u8, "@MED "), (1u8, "@LOW ")] {
        if let Some(tokens) = by_tier.get(&rank).filter(|t| !t.is_empty()) {
            let _ = writeln!(out, "{label}: {}", tokens.join(" | "));
        }
    }
    out.push_str("@STEP_ECONOMICS/1[rule=R132|shell>=60%|sub<=12|task<=25|split>=3_or_120s]\n<!-- KINTSUGI:KMI/1 END -->");
    out
}

/// Render the deterministic `@CREED/1` (`R128`) operational philosophy JSON descriptor.
pub fn render_creed_json() -> String {
    let pillars = JsonArr::new()
        .str("P1:MUTATE")
        .str("P2:SYNTH")
        .str("P3:SCAR")
        .str("P4:PRUNE")
        .str("P5:CONVERGE");
    JsonObj::with_capacity(320)
        .bool("ok", true)
        .str("rule_id", "R128")
        .str(
            "wire",
            "@CREED/1[ver=2.1|axiom=\"MUTATE_OR_STALL: identical_input => identical_failure | TRY_ALL_PICK_BEST: no_new_way => select_best_tested\"|p1=2_STRIKE_PIVOT|p2=2X_TOOL_SYNTH|p3=CRACK_TO_SCAR|p4=SELF_OVERWRITE|p5=TRY_ALL_PICK_BEST]",
        )
        .arr("pillars", pillars)
        .finish()
}

/// Deterministically render the complete verbose Markdown guardrail reference manual
/// from all 36 `BUILTIN_RULES` for empirical subword token comparison against `KMI/1`.
pub fn render_verbose_guardrail_manual() -> String {
    let mut out = String::with_capacity(BUILTIN_RULES.len() * 720 + 512);
    out.push_str(
        "# Kintsugi Governance & Security Guardrail Manual (Full Verbose System Specification)\n\n\
         All autonomous engineering agents must enforce every security, safety, reliability, and \
         correctness rule below across generated code, patches, shell commands, and migrations.\n\n",
    );
    for (idx, rule) in BUILTIN_RULES.iter().enumerate() {
        let op_body = rule
            .kmi_token
            .find('(')
            .and_then(|s| rule.kmi_token.strip_suffix(')').map(|t| &t[s + 1..]))
            .unwrap_or(rule.kmi_token);
        let (anti_pat, req_guard) = op_body.split_once("->").unwrap_or((op_body, "canonical_s3_guard"));
        let pos_code = rule
            .fix_hint
            .strip_prefix("@POS_AST{")
            .and_then(|s| s.strip_suffix('}'))
            .unwrap_or(rule.fix_hint);
        let langs = rule.languages.join(", ");
        let tier_scope = if rule.premium_only { "Grade-S3 Extended" } else { "Core Baseline" };
        let _ = write!(
            out,
            "## {}. Rule {} — `{}` [{} | {}]\n\
             - **Canonical Descriptor:** `{}`\n\
             - **Severity & Tier:** `{}` ({})\n\
             - **Target Languages:** {}\n\
             - **Domain Category:** `{}`\n\
             - **Operational Invariant:** Enforce `{}` across every modified source file, staged diff hunk, and tool invocation before execution.\n\
             - **Security & Reliability Rationale:** Eliminates production defect class `{}` in `{}` workflows by forbidding unguarded `{}` constructs across {} runtimes.\n\
             - **Prohibited Anti-Pattern:** Emitting or retaining `{}` without explicit `{}` enforcement or validated control-plane confinement.\n\
             - **Verified Remediation Template:**\n```\n{}\n```\n\
             - **PreToolUse JIT Enforcement:** Fail-closed `permissionDecision: \"deny\"` whenever rule severity meets or exceeds active blocking threshold; untrusted inline `kintsugi: ignore-file` overrides are rejected.\n\n",
            idx + 1, rule.id, op_body, rule.severity.as_str(), rule.category, rule.title,
            rule.severity.as_str(), tier_scope, langs, rule.category, op_body, rule.id,
            rule.category, anti_pat, langs, anti_pat, req_guard, pos_code,
        );
    }
    out.push_str(
        "## Operational Step-Economics Policy (`R132`)\n\
         Maintain shell batching ratio `>= 60%`, subagent step cap `<= 12`, task step cap `<= 25`, \
         and parallel dispatch only when `>= 3` independent subtasks or estimated duration `>= 120s`.\n",
    );
    out
}

/// Compute empirical token savings between verbose Markdown guardrails and `@KMI/1` wire index.
pub fn compute_token_benchmark() -> TokenBenchmark {
    let kmi_tokens = estimate_tokens_heuristic(&render_kmi_compact_header());
    let verbose_tokens = estimate_tokens_heuristic(&render_verbose_guardrail_manual());
    let reduction_pct = if verbose_tokens > 0 {
        ((verbose_tokens.saturating_sub(kmi_tokens)) as f64 / verbose_tokens as f64) * 100.0
    } else {
        0.0
    };
    TokenBenchmark {
        rules_count: BUILTIN_RULES.len(),
        verbose_tokens,
        kmi_tokens,
        reduction_pct,
        saved_tokens_50_turns: verbose_tokens.saturating_sub(kmi_tokens) * 50,
    }
}
