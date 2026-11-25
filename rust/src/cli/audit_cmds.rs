//! Audit, Memory Integrity, PreToolUse Hook, Step-Economics & Governance subcommands (`rust/src/cli/audit_cmds.rs`).

use std::path::Path;
#[cfg(feature = "audit")]
use std::process;

use kintsugi_core::io_json::write_stdout_str;
#[cfg(feature = "audit")]
use kintsugi_core::io_json::{read_stdin_checked, write_stdout_ln, JsonObj, ENGINE_VERSION};
use kintsugi_core::kml::{infer_kml_lang_from_path, render_kml_builtin_corpus_for_lang};
use kintsugi_core::model::Severity;

use super::{emit_cli_error_json, reject_unknown_flag, ArgCursor, CliToken};

#[cfg(not(feature = "audit"))]
fn require_audit_feature(cmd: &str) -> ! {
    emit_cli_error_json(
        "FEATURE_DISABLED",
        &format!("Subcommand '{cmd}' requires Cargo feature 'audit'"),
        2,
    )
}

pub fn run_s3_audit_cmd(args: &[String]) {
    let mut targets: Vec<&str> = Vec::new();
    let mut format = "json";
    let mut strict_proven = false;

    let mut cur = ArgCursor::for_subcommand(args);
    while let Some(tok) = cur.next_item() {
        match tok {
            CliToken::Positional(p) => targets.push(p),
            CliToken::Flag("--strict-proven") => strict_proven = true,
            CliToken::Flag("--format") => format = cur.parse_format("--format", &["text", "json"]),
            CliToken::Flag(other) => reject_unknown_flag(other),
        }
    }
    if targets.is_empty() {
        targets.push(".");
    }

    #[cfg(feature = "audit")]
    {
        use kintsugi_core::audit::{compute_s3_verdicts, render_s3_audit_json, s3_audit_path_with_mode};
        let mut rep = s3_audit_path_with_mode(Path::new(targets[0]), strict_proven);
        if targets.len() > 1 {
            let mut had_no_input = rep.verdict == "FAIL_NO_INPUT";
            rep.target = targets.join(",");
            for t in &targets[1..] {
                let mut sub = s3_audit_path_with_mode(Path::new(t), strict_proven);
                had_no_input |= sub.verdict == "FAIL_NO_INPUT";
                rep.files_scanned += sub.files_scanned;
                rep.total_functions += sub.total_functions;
                rep.total_classes += sub.total_classes;
                rep.total_seams += sub.total_seams;
                rep.s3_locked_seams += sub.s3_locked_seams;
                rep.proven_s3_seams += sub.proven_s3_seams;
                rep.unproven_seams += sub.unproven_seams;
                rep.unguarded_s0_seams += sub.unguarded_s0_seams;
                rep.ignored_override |= sub.ignored_override;
                rep.ignored_override_files += sub.ignored_override_files;
                rep.missing_targets.append(&mut sub.missing_targets);
                rep.elapsed_ms += sub.elapsed_ms;
                rep.files.append(&mut sub.files);
            }
            if had_no_input || !rep.missing_targets.is_empty() {
                rep.assurance_tier = "NO_INPUT";
                rep.verdict = "FAIL_NO_INPUT";
                rep.strict_verdict = "NO_INPUT";
            } else {
                let (tier, verd, sverd) = compute_s3_verdicts(
                    rep.unguarded_s0_seams,
                    rep.unproven_seams,
                    rep.ignored_override,
                    strict_proven,
                );
                rep.assurance_tier = tier;
                rep.verdict = verd;
                rep.strict_verdict = sverd;
            }
        }
        if format == "text" {
            write_stdout_ln(&format!(
                "Kintsugi-RS v{ENGINE_VERSION} Grade-S3 Seam Audit (strict_proven={strict_proven}): files={} functions={} classes={} proven_s3={}/{} unproven={} S0_unguarded={} elapsed={:.3}ms tier={} verdict={} strict_verdict={}",
                rep.files_scanned, rep.total_functions, rep.total_classes, rep.proven_s3_seams,
                rep.total_seams, rep.unproven_seams, rep.unguarded_s0_seams, rep.elapsed_ms, rep.assurance_tier, rep.verdict, rep.strict_verdict
            ));
            for f in &rep.files {
                write_stdout_ln(&format!(
                    "  {} | sha={} | {:.2}ms | fn/cls={}/{} | proven={}/{} unproven={} S0={} | {}",
                    f.file_path, f.manifest_sha, f.elapsed_ms, f.functions_count, f.classes_count,
                    f.proven_s3_seams, f.total_seams, f.unproven_seams, f.unguarded_s0_seams, f.verdict
                ));
                for fs in f.failing_seams.iter().take(16) {
                    write_stdout_ln(&format!(
                        "    line {}: [{} {}] {} | Fix: {}",
                        fs.seam_line, fs.tier, fs.seam_kind, fs.reason, fs.fix_hint
                    ));
                }
            }
        } else {
            write_stdout_ln(&render_s3_audit_json(&rep));
        }
        if rep.verdict == "FAIL_NO_INPUT" {
            process::exit(2);
        }
        if rep.verdict != "PASS_S3_LOCKED" {
            process::exit(1);
        }
    }
    #[cfg(not(feature = "audit"))]
    {
        let _ = (targets, format, strict_proven);
        require_audit_feature("s3-audit");
    }
}

pub fn run_memories_verify_cmd(args: &[String]) {
    let (mut workspace, mut format) = (".", "json");
    let mut cur = ArgCursor::for_subcommand(args);
    while let Some(tok) = cur.next_item() {
        match tok {
            CliToken::Positional(p) => workspace = p,
            CliToken::Flag("--format") => format = cur.parse_format("--format", &["text", "json"]),
            CliToken::Flag(other) => reject_unknown_flag(other),
        }
    }

    #[cfg(feature = "audit")]
    {
        use kintsugi_core::audit::{render_memories_verify_json, verify_memories_readonly};
        let rep = verify_memories_readonly(Path::new(workspace));
        if format == "text" {
            write_stdout_ln(&format!(
                "Kintsugi-RS v{ENGINE_VERSION} Read-Only Memory Integrity: status={} ok={} root={} index_exists={} index_bytes={} fnv64={} lessons={} archives={} changelogs={} backups={} symlinks={} corrupt={} elapsed={:.3}ms",
                rep.status, rep.ok, rep.workspace_root, rep.memories_index_exists, rep.memories_index_bytes,
                rep.memories_index_fnv64, rep.lessons_count, rep.archive_files_count, rep.changelogs_count,
                rep.backups_dirs_count, rep.symlinks_detected, rep.empty_or_corrupt_files, rep.elapsed_ms
            ));
        } else {
            write_stdout_ln(&render_memories_verify_json(&rep));
        }
        if !rep.ok {
            process::exit(1);
        }
    }
    #[cfg(not(feature = "audit"))]
    {
        let _ = (workspace, format);
        require_audit_feature("memories-verify");
    }
}

pub fn run_step_audit_cmd(args: &[String]) {
    let mut target = ".";
    let (mut max_sessions, mut sub_cap, mut task_cap) = (25usize, 12usize, 25usize);
    let (mut wire_only, mut allow_bloat) = (false, false);
    let mut target_shell = 60.0f64;

    let mut cur = ArgCursor::for_subcommand(args);
    while let Some(tok) = cur.next_item() {
        match tok {
            CliToken::Positional(p) => target = p,
            CliToken::Flag("--max-sessions") => max_sessions = cur.parse_usize("--max-sessions").max(1),
            CliToken::Flag("--sub-cap") => sub_cap = cur.parse_usize("--sub-cap").max(1),
            CliToken::Flag("--task-cap") => task_cap = cur.parse_usize("--task-cap").max(1),
            CliToken::Flag("--target-shell") => {
                target_shell = cur.parse_f64("--target-shell");
                if !(0.0..=100.0).contains(&target_shell) {
                    emit_cli_error_json("INVALID_RANGE", "--target-shell must be within [0.0, 100.0]", 2);
                }
            }
            CliToken::Flag("--wire") => wire_only = true,
            CliToken::Flag("--allow-bloat") => allow_bloat = true,
            CliToken::Flag(other) => reject_unknown_flag(other),
        }
    }

    #[cfg(feature = "audit")]
    {
        use kintsugi_core::audit::{audit_step_economics_path, render_step_audit_json};
        let rep = audit_step_economics_path(Path::new(target), max_sessions, sub_cap, task_cap, target_shell);
        write_stdout_ln(&if wire_only { rep.wire.clone() } else { render_step_audit_json(&rep) });
        let passed = if allow_bloat { rep.data_ok } else { rep.policy_ok };
        if !passed {
            process::exit(1);
        }
    }
    #[cfg(not(feature = "audit"))]
    {
        let _ = (target, max_sessions, sub_cap, task_cap, target_shell, wire_only, allow_bloat);
        require_audit_feature("step-audit");
    }
}

pub fn run_hook_cmd(args: &[String]) {
    let mut mode = "claude-pre-tool";
    let mut block_on = Severity::High;
    let mut workspace: Option<&str> = None;
    let mut telemetry_store: Option<&str> = None;
    let mut exit_on_deny = false;
    let mut include_low_tier = false;
    let mut max_tokens: usize = 320;

    let mut cur = ArgCursor::for_subcommand(args);
    while let Some(tok) = cur.next_item() {
        match tok {
            CliToken::Positional("claude-pre-tool") => mode = "claude-pre-tool",
            CliToken::Positional("claude-post-read") => mode = "claude-post-read",
            CliToken::Flag("--block-on") => block_on = cur.parse_severity("--block-on"),
            CliToken::Flag("--workspace") => workspace = Some(cur.require_value("--workspace")),
            CliToken::Flag("--telemetry-store") => telemetry_store = Some(cur.require_value("--telemetry-store")),
            CliToken::Flag("--exit-on-deny") => exit_on_deny = true,
            CliToken::Flag("--low-tier") => include_low_tier = true,
            CliToken::Flag("--max-tokens") => {
                max_tokens = cur.parse_usize("--max-tokens");
                if max_tokens == 0 {
                    emit_cli_error_json("INVALID_MAX_TOKENS", "--max-tokens must be > 0", 2);
                }
            }
            other => reject_unknown_flag(other.as_str()),
        }
    }

    #[cfg(feature = "audit")]
    {
        let stdin_buf = read_stdin_checked().unwrap_or_else(|msg| {
            let err_json = JsonObj::new()
                .bool("ok", false)
                .str("schema_version", ENGINE_VERSION)
                .str("code", "STDIN_IO_ERROR")
                .str("error", &msg)
                .finish();
            kintsugi_core::io_json::write_stderr_safe(&err_json);
            let inner = JsonObj::new()
                .str("hookEventName", if mode == "claude-post-read" { "PostToolUse" } else { "PreToolUse" })
                .str("permissionDecision", "deny")
                .str("permissionDecisionReason", &msg)
                .finish();
            write_stdout_ln(&JsonObj::new().raw("hookSpecificOutput", &inner).finish());
            process::exit(2);
        });
        if mode == "claude-post-read" {
            let out = kintsugi_core::audit::context_envelope::evaluate_post_read_hook_json_with_workspace_telemetry(
                &stdin_buf,
                include_low_tier,
                max_tokens,
                workspace.map(Path::new),
                telemetry_store.map(Path::new),
            )
            .unwrap_or_else(|e| emit_cli_error_json("TELEMETRY_ERROR", &e, 2));
            write_stdout_ln(&out);
            return;
        }
        let eval = kintsugi_core::audit::evaluate_pre_tool_detailed(
            &stdin_buf,
            block_on,
            workspace.map(Path::new),
        );
        write_stdout_ln(&eval.json);
        if exit_on_deny && !eval.allowed {
            process::exit(1);
        }
    }
    #[cfg(not(feature = "audit"))]
    {
        let _ = (mode, block_on, workspace, telemetry_store, exit_on_deny, include_low_tier, max_tokens);
        require_audit_feature("hook");
    }
}

pub fn run_creed_cmd(args: &[String]) {
    let mut cur = ArgCursor::for_subcommand(args);
    if let Some(tok) = cur.next_item() {
        reject_unknown_flag(tok.as_str());
    }
    #[cfg(feature = "audit")]
    write_stdout_ln(&kintsugi_core::audit::render_creed_json());
    #[cfg(not(feature = "audit"))]
    require_audit_feature("creed");
}

pub fn run_swarm_plan_cmd(args: &[String]) {
    let mut words: Vec<&str> = Vec::new();
    let mut cur = ArgCursor::for_subcommand(args);
    while let Some(tok) = cur.next_item() {
        match tok {
            CliToken::Positional(w) => words.push(w),
            CliToken::Flag(other) => reject_unknown_flag(other),
        }
    }
    let task_desc = if words.is_empty() { "multi-workstream task".to_string() } else { words.join(" ") };
    #[cfg(feature = "audit")]
    write_stdout_ln(&kintsugi_core::audit::render_swarm_plan_json(&task_desc));
    #[cfg(not(feature = "audit"))]
    {
        let _ = task_desc;
        require_audit_feature("swarm-plan");
    }
}

pub fn run_compress_cmd(args: &[String]) {
    let mut kml_mode = false;
    let mut lang_filter: Option<String> = None;
    let mut cur = ArgCursor::for_subcommand(args);
    while let Some(tok) = cur.next_item() {
        match tok {
            CliToken::Flag("--kml") => kml_mode = true,
            CliToken::Flag("--lang") => lang_filter = Some(cur.require_value("--lang").to_string()),
            CliToken::Flag("--for-file") => {
                let p = cur.require_value("--for-file");
                lang_filter = infer_kml_lang_from_path(Path::new(p)).map(|s| s.to_string());
            }
            other => reject_unknown_flag(other.as_str()),
        }
    }
    if kml_mode {
        write_stdout_str(&render_kml_builtin_corpus_for_lang(lang_filter.as_deref()));
    } else {
        #[cfg(feature = "audit")]
        write_stdout_ln(&kintsugi_core::audit::render_kmi_compact_header());
        #[cfg(not(feature = "audit"))]
        require_audit_feature("compress");
    }
}

pub fn run_capsule_cmd(args: &[String]) {
    let mut target: Option<&str> = None;
    let mut capsules_file: Option<&str> = None;
    let mut max_capsules: usize = 8;
    let mut format = "compact";

    let mut cur = ArgCursor::for_subcommand(args);
    while let Some(tok) = cur.next_item() {
        match tok {
            CliToken::Positional(p) => {
                if target.is_some() {
                    emit_cli_error_json("UNEXPECTED_POSITIONAL", &format!("Unexpected extra argument '{p}'"), 2);
                }
                target = Some(p);
            }
            CliToken::Flag("--capsules-file") => capsules_file = Some(cur.require_value("--capsules-file")),
            CliToken::Flag("--max-capsules") => {
                max_capsules = cur.parse_usize("--max-capsules");
                if max_capsules == 0 {
                    emit_cli_error_json("INVALID_MAX_CAPSULES", "--max-capsules must be > 0", 2);
                }
            }
            CliToken::Flag("--format") => format = cur.parse_format("--format", &["compact", "json"]),
            CliToken::Flag(other) => reject_unknown_flag(other),
        }
    }
    let Some(target_path) = target else {
        emit_cli_error_json("MISSING_TARGET", "Usage: kintsugi-rs capsule <FILE_PATH> [--capsules-file PATH] [--max-capsules N] [--format compact|json]", 2);
    };

    #[cfg(feature = "audit")]
    {
        use kintsugi_core::audit::{load_custom_capsules_json, match_capsules_for_file, render_capsule_report_json};
        let extra = match capsules_file {
            Some(cf) => load_custom_capsules_json(Path::new(cf))
                .unwrap_or_else(|e| emit_cli_error_json("INVALID_CAPSULES_FILE", &e, 2)),
            None => Vec::new(),
        };
        let rep = match_capsules_for_file(Path::new(target_path), &extra, max_capsules)
            .unwrap_or_else(|e| emit_cli_error_json("IO_ERROR", &e, 2));
        if format == "json" {
            write_stdout_ln(&render_capsule_report_json(&rep));
        } else if !rep.compact_text.is_empty() {
            write_stdout_ln(&rep.compact_text);
        }
    }
    #[cfg(not(feature = "audit"))]
    {
        let _ = (target_path, capsules_file, max_capsules, format);
        require_audit_feature("capsule");
    }
}

pub fn run_context_cmd(args: &[String]) {
    let mut target: Option<&str> = None;
    let mut capsules_file: Option<&str> = None;
    let mut workspace: Option<&str> = None;
    let mut telemetry_store: Option<&str> = None;
    let mut include_low_tier = false;
    let mut max_tokens: usize = 320;
    let mut format = "json";

    let mut cur = ArgCursor::for_subcommand(args);
    while let Some(tok) = cur.next_item() {
        match tok {
            CliToken::Positional(p) => {
                if target.is_some() {
                    emit_cli_error_json("UNEXPECTED_POSITIONAL", &format!("Unexpected extra argument '{p}'"), 2);
                }
                target = Some(p);
            }
            CliToken::Flag("--capsules-file") => capsules_file = Some(cur.require_value("--capsules-file")),
            CliToken::Flag("--workspace") => workspace = Some(cur.require_value("--workspace")),
            CliToken::Flag("--telemetry-store") => telemetry_store = Some(cur.require_value("--telemetry-store")),
            CliToken::Flag("--low-tier") => include_low_tier = true,
            CliToken::Flag("--max-tokens") => {
                max_tokens = cur.parse_usize("--max-tokens");
                if max_tokens == 0 {
                    emit_cli_error_json("INVALID_MAX_TOKENS", "--max-tokens must be > 0", 2);
                }
            }
            CliToken::Flag("--format") => format = cur.parse_format("--format", &["json", "compact"]),
            CliToken::Flag(other) => reject_unknown_flag(other),
        }
    }
    let Some(target_path) = target else {
        emit_cli_error_json("MISSING_TARGET", "Usage: kintsugi-rs context <FILE_PATH> [--low-tier] [--capsules-file PATH] [--telemetry-store PATH] [--max-tokens N] [--format json|compact]", 2);
    };

    #[cfg(feature = "audit")]
    {
        use kintsugi_core::audit::context_envelope::build_context_envelope_for_file_with_telemetry;
        use kintsugi_core::audit::{load_custom_capsules_json, render_context_envelope_json};
        let extra = match capsules_file {
            Some(cf) => load_custom_capsules_json(Path::new(cf))
                .unwrap_or_else(|e| emit_cli_error_json("INVALID_CAPSULES_FILE", &e, 2)),
            None => Vec::new(),
        };
        let env = build_context_envelope_for_file_with_telemetry(
            Path::new(target_path),
            workspace.map(Path::new),
            &extra,
            include_low_tier,
            max_tokens,
            telemetry_store.map(Path::new),
        )
        .unwrap_or_else(|e| emit_cli_error_json("IO_ERROR", &e, 2));
        if format == "json" {
            write_stdout_ln(&render_context_envelope_json(&env));
        } else if !env.compact_context.is_empty() {
            write_stdout_ln(&env.compact_context);
        }
    }
    #[cfg(not(feature = "audit"))]
    {
        let _ = (target_path, capsules_file, workspace, telemetry_store, include_low_tier, max_tokens, format);
        require_audit_feature("context");
    }
}

pub fn run_task_pack_cmd(args: &[String]) {
    let mut targets: Vec<&str> = Vec::new();
    let mut telemetry_store: Option<&str> = None;
    let mut include_low_tier = true;
    let mut max_tokens: usize = 480;
    let mut format = "compact";

    let mut cur = ArgCursor::for_subcommand(args);
    while let Some(tok) = cur.next_item() {
        match tok {
            CliToken::Positional(p) => targets.push(p),
            CliToken::Flag("--telemetry-store") => telemetry_store = Some(cur.require_value("--telemetry-store")),
            CliToken::Flag("--low-tier") => include_low_tier = true,
            CliToken::Flag("--no-low-tier") => include_low_tier = false,
            CliToken::Flag("--max-tokens") => {
                max_tokens = cur.parse_usize("--max-tokens");
                if max_tokens == 0 {
                    emit_cli_error_json("INVALID_MAX_TOKENS", "--max-tokens must be > 0", 2);
                }
            }
            CliToken::Flag("--format") => format = cur.parse_format("--format", &["compact", "json"]),
            CliToken::Flag(other) => reject_unknown_flag(other),
        }
    }
    if targets.is_empty() {
        emit_cli_error_json("MISSING_TARGET", "Usage: kintsugi-rs task-pack <FILE_PATH...> [--low-tier|--no-low-tier] [--telemetry-store PATH] [--max-tokens N] [--format compact|json]", 2);
    }

    #[cfg(feature = "audit")]
    {
        use kintsugi_core::audit::context_envelope::build_task_pack_with_telemetry;
        use kintsugi_core::audit::render_context_envelope_json;
        use kintsugi_core::io_json::JsonArr;
        let target_paths: Vec<&Path> = targets.iter().map(|t| Path::new(*t)).collect();
        let pack = build_task_pack_with_telemetry(
            &target_paths,
            include_low_tier,
            max_tokens,
            telemetry_store.map(Path::new),
        )
        .unwrap_or_else(|e| emit_cli_error_json("IO_ERROR", &e, 2));
        if format == "json" {
            let mut files_json = JsonArr::new();
            let mut envs_json = JsonArr::new();
            for env in &pack.files {
                let rendered = render_context_envelope_json(env);
                files_json = files_json.raw(&rendered);
                envs_json = envs_json.raw(&rendered);
            }
            let out = JsonObj::with_capacity(pack.packet.len() + 512)
                .bool("ok", true)
                .str("schema_version", ENGINE_VERSION)
                .bool("low_tier_enabled", include_low_tier)
                .usize("max_tokens", max_tokens)
                .usize("files_count", pack.files.len())
                .usize("requested_files_count", targets.len())
                .usize("total_tokens", pack.total_tokens)
                .usize("estimated_tokens", pack.total_tokens)
                .arr("files", files_json)
                .arr("envelopes", envs_json)
                .str("packet", &pack.packet)
                .finish();
            write_stdout_ln(&out);
        } else if !pack.packet.is_empty() {
            write_stdout_ln(&pack.packet);
        }
    }
    #[cfg(not(feature = "audit"))]
    {
        let _ = (targets, telemetry_store, include_low_tier, max_tokens, format);
        require_audit_feature("task-pack");
    }
}

pub fn run_lexicon_cmd(args: &[String]) {
    let mut target: Option<&str> = None;
    let mut show_all = false;
    let mut lang_override: Option<&str> = None;
    let mut max_entries: usize = 4;
    let mut format = "compact";

    let mut cur = ArgCursor::for_subcommand(args);
    while let Some(tok) = cur.next_item() {
        match tok {
            CliToken::Positional(p) => {
                if target.is_some() {
                    emit_cli_error_json("UNEXPECTED_POSITIONAL", &format!("Unexpected extra argument '{p}'"), 2);
                }
                target = Some(p);
            }
            CliToken::Flag("--all") => show_all = true,
            CliToken::Flag("--lang") => lang_override = Some(cur.require_value("--lang")),
            CliToken::Flag("--max-entries") => {
                max_entries = cur.parse_usize("--max-entries");
                if max_entries == 0 {
                    emit_cli_error_json("INVALID_MAX_ENTRIES", "--max-entries must be > 0", 2);
                }
            }
            CliToken::Flag("--format") => format = cur.parse_format("--format", &["compact", "json"]),
            CliToken::Flag(other) => reject_unknown_flag(other),
        }
    }

    #[cfg(feature = "audit")]
    {
        use kintsugi_core::audit::{
            match_low_tier_lexicon_for_file, render_all_lexicon_json, render_lexicon_report_json,
            LOW_TIER_PITFALL_LEXICON,
        };
        if show_all || target.is_none() {
            if format == "json" {
                write_stdout_ln(&render_all_lexicon_json());
            } else {
                for e in LOW_TIER_PITFALL_LEXICON {
                    write_stdout_ln(&e.render_compact());
                }
            }
            return;
        }
        let rep = match_low_tier_lexicon_for_file(Path::new(target.unwrap()), lang_override, max_entries)
            .unwrap_or_else(|e| emit_cli_error_json("IO_ERROR", &e, 2));
        if format == "json" {
            write_stdout_ln(&render_lexicon_report_json(&rep));
        } else if !rep.compact_text.is_empty() {
            write_stdout_ln(&rep.compact_text);
        }
    }
    #[cfg(not(feature = "audit"))]
    {
        let _ = (target, show_all, lang_override, max_entries, format);
        require_audit_feature("lexicon");
    }
}

pub fn run_telemetry_cmd(args: &[String]) {
    let mut cur = ArgCursor::for_subcommand(args);
    let mut action: Option<&str> = None;
    let mut store: &str = ".kintsugi/delivery_telemetry.json";
    let mut client: &str = "";
    let mut stage: &str = "";
    let mut session_id: &str = "";
    let mut envelope_id: &str = "";
    let mut source_digest: &str = "";
    let mut patch_digest: &str = "";
    let mut capsule_ids_raw: &str = "";
    let mut pitfall_ids_raw: &str = "";
    let mut estimated_tokens: usize = 0;
    let mut passed: Option<bool> = None;

    while let Some(tok) = cur.next_item() {
        match tok {
            CliToken::Flag("--store") => store = cur.require_value("--store"),
            CliToken::Flag("--client") => client = cur.require_value("--client"),
            CliToken::Flag("--stage") => stage = cur.require_value("--stage"),
            CliToken::Flag("--session-id") => session_id = cur.require_value("--session-id"),
            CliToken::Flag("--envelope-id") => envelope_id = cur.require_value("--envelope-id"),
            CliToken::Flag("--source-digest") => source_digest = cur.require_value("--source-digest"),
            CliToken::Flag("--patch-digest") => patch_digest = cur.require_value("--patch-digest"),
            CliToken::Flag("--capsule-ids") => capsule_ids_raw = cur.require_value("--capsule-ids"),
            CliToken::Flag("--pitfall-ids") => pitfall_ids_raw = cur.require_value("--pitfall-ids"),
            CliToken::Flag("--tokens") => estimated_tokens = cur.parse_usize("--tokens"),
            CliToken::Flag("--passed") => {
                let raw = cur.require_value("--passed");
                passed = match raw {
                    "true" | "1" | "yes" => Some(true),
                    "false" | "0" | "no" => Some(false),
                    _ => emit_cli_error_json("INVALID_BOOL", &format!("Invalid --passed value '{raw}' (expected true|false)"), 2),
                };
            }
            CliToken::Positional(pos) if action.is_none() && matches!(pos, "record" | "report") => {
                action = Some(pos);
            }
            CliToken::Flag(f) => reject_unknown_flag(f),
            CliToken::Positional(p) => reject_unknown_flag(p),
        }
    }

    let act = action.unwrap_or("report");
    #[cfg(feature = "audit")]
    {
        use kintsugi_core::audit::{record_telemetry_event, render_telemetry_report_json};
        let split_csv = |s: &str| -> Vec<String> {
            s.split(',')
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(str::to_string)
                .collect()
        };
        if act == "record" {
            let caps = split_csv(capsule_ids_raw);
            let pits = split_csv(pitfall_ids_raw);
            let out = record_telemetry_event(
                Path::new(store),
                client,
                stage,
                session_id,
                envelope_id,
                source_digest,
                patch_digest,
                &caps,
                &pits,
                estimated_tokens,
                passed,
            )
            .unwrap_or_else(|e| emit_cli_error_json("TELEMETRY_ERROR", &e, 2));
            write_stdout_ln(&out);
            return;
        }
        let out = render_telemetry_report_json(Path::new(store))
            .unwrap_or_else(|e| emit_cli_error_json("TELEMETRY_ERROR", &e, 2));
        write_stdout_ln(&out);
    }
    #[cfg(not(feature = "audit"))]
    {
        let _ = (
            act, store, client, stage, session_id, envelope_id, source_digest, patch_digest,
            capsule_ids_raw, pitfall_ids_raw, estimated_tokens, passed,
        );
        require_audit_feature("telemetry");
    }
}
