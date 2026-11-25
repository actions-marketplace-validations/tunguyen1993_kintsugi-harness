//! `@STEP_ECONOMICS/1` (`R132`) Bounded Transcript Step Auditor & `@SWARM_DISPATCH/1` (`R131`) Planner.

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::io_json::{JsonArr, JsonObj, ENGINE_VERSION};
use crate::json_dom::{parse_json_value, JsonValue};
use crate::policy::sha256_hex;

/// Maximum per-transcript file size (`32 MiB`) accepted by `step-audit`.
pub const MAX_TRANSCRIPT_FILE_BYTES: u64 = 32 * 1024 * 1024;
/// Maximum single JSONL line byte length (`1 MiB`) read into memory before bounded drain.
pub const MAX_TRANSCRIPT_LINE_BYTES: usize = 1024 * 1024;
/// Maximum cumulative parsed JSONL records across a single `step-audit` invocation.
pub const MAX_TRANSCRIPT_RECORDS: usize = 50_000;
/// Maximum cumulative transcript bytes (`128 MiB`) read across a single `step-audit` invocation.
pub const MAX_TOTAL_TRANSCRIPT_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct StepAuditReport {
    pub ok: bool,
    pub data_ok: bool,
    pub policy_ok: bool,
    pub target: String,
    pub explicit_manifest_sha256: String,
    pub grade: String,
    pub candidate_files: usize,
    pub parsed_files: usize,
    pub malformed_lines: usize,
    pub truncated_sessions: usize,
    pub sessions_scanned: usize,
    pub main_sessions_count: usize,
    pub subagent_runs_count: usize,
    pub total_planner_steps: usize,
    pub total_tool_calls: usize,
    pub total_shell_calls: usize,
    pub total_error_steps: usize,
    pub overall_shell_call_ratio_pct: f64,
    pub overall_error_step_ratio_pct: f64,
    pub main_avg_steps_per_turn: f64,
    pub subagent_avg_steps: f64,
    pub subagent_max_steps: usize,
    pub subagent_cap_breaches_count: usize,
    pub cap_breaches: usize,
    pub subagent_step_cap: usize,
    pub task_step_cap: usize,
    pub target_shell_pct: f64,
    pub elapsed_ms: f64,
    pub wire: String,
}

/// Deterministic `mtime`-independent configuration for auditing an explicit list of transcript files.
#[derive(Debug, Clone)]
pub struct AuditStepEconomicsWithFiles {
    pub target_label: String,
    pub files: Vec<PathBuf>,
    pub subagent_step_cap: usize,
    pub task_step_cap: usize,
    pub target_shell_pct: f64,
}

impl AuditStepEconomicsWithFiles {
    pub fn new(files: Vec<PathBuf>) -> Self {
        Self {
            target_label: "explicit_manifest".to_string(),
            files,
            subagent_step_cap: 12,
            task_step_cap: 25,
            target_shell_pct: 60.0,
        }
    }

    pub fn run(&self) -> StepAuditReport {
        audit_step_economics_with_label(
            &self.target_label,
            &self.files,
            self.subagent_step_cap,
            self.task_step_cap,
            self.target_shell_pct,
        )
    }
}

struct ParsedTranscriptLine {
    msg_type: Option<String>,
    status: Option<String>,
    tool_names: Vec<String>,
    is_truncated: bool,
}

enum BoundedLine {
    Eof,
    Line(Vec<u8>),
    Oversized,
    IoErr,
}

/// Read a single `\n`-delimited line capping in-memory allocation strictly at `max_bytes`.
fn read_bounded_jsonl_line<R: BufRead>(reader: &mut R, max_bytes: usize) -> BoundedLine {
    let mut buf = Vec::new();
    let mut over = false;
    loop {
        let chunk = match reader.fill_buf() {
            Ok([]) => {
                return if buf.is_empty() && !over {
                    BoundedLine::Eof
                } else if over {
                    BoundedLine::Oversized
                } else {
                    BoundedLine::Line(buf)
                };
            }
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return BoundedLine::IoErr,
        };
        if let Some(nl) = chunk.iter().position(|&b| b == b'\n') {
            if !over {
                if buf.len() + nl > max_bytes {
                    over = true;
                    buf.clear();
                } else {
                    buf.extend_from_slice(&chunk[..nl]);
                }
            }
            reader.consume(nl + 1);
            return if over { BoundedLine::Oversized } else { BoundedLine::Line(buf) };
        }
        let avail = chunk.len();
        if !over {
            if buf.len() + avail > max_bytes {
                over = true;
                buf.clear();
            } else {
                buf.extend_from_slice(chunk);
            }
        }
        reader.consume(avail);
    }
}

fn parse_jsonl_transcript_line(trimmed: &str) -> Option<ParsedTranscriptLine> {
    let Ok(JsonValue::Object(obj)) = parse_json_value(trimmed) else { return None };
    let msg_type = obj.get("type").and_then(|v| v.as_str()).map(String::from);
    let status = obj.get("status").and_then(|v| v.as_str()).map(String::from);
    let mut tool_names = Vec::new();
    if let Some(arr) = obj.get("tool_calls").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(name) = item.as_object().and_then(|m| m.get("name")).and_then(|v| v.as_str()) {
                tool_names.push(name.to_string());
            }
        }
    }
    let is_truncated = obj.get("truncated_fields").is_some_and(|v| {
        v.as_array().is_some_and(|a| !a.is_empty()) || v.as_bool() == Some(true)
    }) || obj.get("truncated").and_then(|v| v.as_bool()) == Some(true);

    Some(ParsedTranscriptLine { msg_type, status, tool_names, is_truncated })
}

fn compute_transcript_manifest_sha256(files: &[PathBuf]) -> String {
    let mut preimage = Vec::new();
    for (index, path) in files.iter().enumerate() {
        preimage.extend_from_slice(index.to_string().as_bytes());
        preimage.push(b':');
        match crate::io_json::read_regular_bytes_fd_verified(
            path,
            MAX_TRANSCRIPT_FILE_BYTES as usize,
        ) {
            Ok(bytes) => {
                preimage.push(b'1');
                preimage.extend_from_slice(bytes.len().to_string().as_bytes());
                preimage.push(b':');
                preimage.extend_from_slice(&bytes);
            }
            Err(_) => {
                preimage.push(b'0');
            }
        }
        preimage.push(b'\n');
    }
    sha256_hex(&preimage)
}

fn collect_jsonl_candidates(dir: &Path, out: &mut Vec<(u128, PathBuf)>, depth: usize) {
    if depth > 4 { return; }
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else { continue };
        if meta.file_type().is_symlink() { continue; }
        if meta.is_dir() {
            let name_str = entry.file_name();
            let ns = name_str.to_string_lossy();
            if ns == ".git" || ns == "target" || ns == "node_modules" { continue; }
            collect_jsonl_candidates(&path, out, depth + 1);
        } else if meta.is_file() && path.extension().and_then(|s| s.to_str()) == Some("jsonl") {
            let mtime_ns = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_nanos()).unwrap_or(0);
            out.push((mtime_ns, path));
        }
    }
}

fn discover_transcripts_for_step_audit(target: &Path, max_sessions: usize) -> Vec<PathBuf> {
    let Ok(meta) = fs::symlink_metadata(target) else { return Vec::new() };
    if meta.file_type().is_symlink() { return Vec::new(); }
    if meta.is_file() { return vec![target.to_path_buf()]; }
    if !meta.is_dir() { return Vec::new(); }

    let mut brain_style: Vec<(u128, PathBuf)> = Vec::new();
    if let Ok(entries) = fs::read_dir(target) {
        for entry in entries.flatten() {
            let sub = entry.path();
            let Ok(sm) = fs::symlink_metadata(&sub) else { continue };
            if sm.file_type().is_symlink() || !sm.is_dir() { continue; }
            let cand = sub.join(".system_generated").join("logs").join("transcript.jsonl");
            if let Ok(cm) = fs::symlink_metadata(&cand) {
                if !cm.file_type().is_symlink() && cm.is_file() {
                    let mtime_ns = cm.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_nanos()).unwrap_or(0);
                    brain_style.push((mtime_ns, cand));
                }
            }
        }
    }

    let mut candidates = if !brain_style.is_empty() {
        brain_style
    } else {
        let mut generic: Vec<(u128, PathBuf)> = Vec::new();
        collect_jsonl_candidates(target, &mut generic, 0);
        generic
    };

    candidates.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    candidates.into_iter().take(max_sessions.max(1)).map(|(_, p)| p).collect()
}

/// Audit an explicit deterministic list of transcript files independent of `mtime`.
pub fn audit_step_economics_files(
    files: &[PathBuf],
    subagent_step_cap: usize,
    task_step_cap: usize,
    target_shell_pct: f64,
) -> StepAuditReport {
    audit_step_economics_with_label("explicit_manifest", files, subagent_step_cap, task_step_cap, target_shell_pct)
}

fn audit_step_economics_with_label(
    target_label: &str,
    files: &[PathBuf],
    subagent_step_cap: usize,
    task_step_cap: usize,
    target_shell_pct: f64,
) -> StepAuditReport {
    let t0 = Instant::now();
    let candidate_files = files.len();
    let explicit_manifest_sha256 = compute_transcript_manifest_sha256(files);

    let (mut parsed_files, mut malformed_lines, mut truncated_sessions, mut sessions_scanned) = (0, 0, 0, 0);
    let (mut main_sessions_count, mut subagent_runs_count) = (0usize, 0usize);
    let (mut total_planner_steps, mut total_tool_calls, mut total_shell_calls, mut total_error_steps) = (0, 0, 0, 0);
    let (mut main_steps_per_turn_sum, mut subagent_steps_sum, mut subagent_max_steps) = (0.0f64, 0usize, 0usize);
    let (mut subagent_cap_breaches_count, mut cap_breaches) = (0usize, 0usize);
    let (mut total_bytes_read, mut total_records_seen) = (0u64, 0usize);

    let mut sorted_files = files.to_vec();
    sorted_files.sort();

    for tf in &sorted_files {
        if total_bytes_read >= MAX_TOTAL_TRANSCRIPT_BYTES || total_records_seen >= MAX_TRANSCRIPT_RECORDS {
            truncated_sessions += 1;
            break;
        }
        let Ok(meta) = fs::symlink_metadata(tf) else { continue };
        if meta.file_type().is_symlink() || !meta.is_file() { continue; }
        if meta.len() > MAX_TRANSCRIPT_FILE_BYTES {
            malformed_lines += 1;
            truncated_sessions += 1;
            continue;
        }
        let rem_total = MAX_TOTAL_TRANSCRIPT_BYTES.saturating_sub(total_bytes_read);
        let file_cap = MAX_TRANSCRIPT_FILE_BYTES.min(rem_total);
        let Ok(file) = fs::File::open(tf) else { continue };
        let Ok(handle_meta) = file.metadata() else { continue };
        if !handle_meta.is_file() {
            continue;
        }
        let Ok(path_meta) = fs::symlink_metadata(tf) else { continue };
        if path_meta.file_type().is_symlink() || !path_meta.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if handle_meta.dev() != path_meta.dev() || handle_meta.ino() != path_meta.ino() {
                continue;
            }
        }
        let mut reader = BufReader::new(file.take(file_cap));

        let (mut valid_records, mut session_truncated, mut user_turns) =
            (0usize, file_cap < handle_meta.len(), 0usize);
        let (mut planner_steps, mut tool_calls, mut shell_calls, mut error_steps) = (0usize, 0usize, 0usize, 0usize);

        loop {
            if total_records_seen >= MAX_TRANSCRIPT_RECORDS {
                session_truncated = true;
                break;
            }
            match read_bounded_jsonl_line(&mut reader, MAX_TRANSCRIPT_LINE_BYTES) {
                BoundedLine::Eof => break,
                BoundedLine::IoErr => { malformed_lines += 1; break; }
                BoundedLine::Oversized => {
                    total_bytes_read = total_bytes_read.saturating_add(MAX_TRANSCRIPT_LINE_BYTES as u64);
                    malformed_lines += 1;
                    session_truncated = true;
                }
                BoundedLine::Line(raw_bytes) => {
                    total_bytes_read = total_bytes_read.saturating_add(raw_bytes.len() as u64 + 1);
                    let Ok(s) = std::str::from_utf8(&raw_bytes) else { malformed_lines += 1; continue; };
                    let trimmed = s.trim();
                    if trimmed.is_empty() { continue; }
                    let Some(rec) = parse_jsonl_transcript_line(trimmed) else {
                        if !session_truncated {
                            malformed_lines += 1;
                        }
                        continue;
                    };
                    valid_records += 1;
                    total_records_seen += 1;
                    if rec.is_truncated { session_truncated = true; }
                    if rec.msg_type.as_deref() == Some("USER_INPUT") {
                        user_turns += 1;
                    } else if rec.msg_type.as_deref() == Some("PLANNER_RESPONSE") {
                        planner_steps += 1;
                        for tn in &rec.tool_names {
                            tool_calls += 1;
                            if matches!(tn.as_str(), "run_command" | "shell" | "bash" | "exec_command") { shell_calls += 1; }
                        }
                        if rec.status.as_deref() == Some("ERROR") { error_steps += 1; }
                    }
                }
            }
        }

        if valid_records == 0 {
            if session_truncated { truncated_sessions += 1; }
            continue;
        }
        parsed_files += 1;
        sessions_scanned += 1;
        if session_truncated { truncated_sessions += 1; }
        total_planner_steps += planner_steps;
        total_tool_calls += tool_calls;
        total_shell_calls += shell_calls;
        total_error_steps += error_steps;

        if user_turns >= 2 {
            main_sessions_count += 1;
            let per_turn = (planner_steps as f64) / (user_turns as f64);
            main_steps_per_turn_sum += per_turn;
            if per_turn > (task_step_cap as f64) { cap_breaches += 1; }
        } else {
            subagent_runs_count += 1;
            subagent_steps_sum += planner_steps;
            if planner_steps > subagent_max_steps { subagent_max_steps = planner_steps; }
            if planner_steps > subagent_step_cap { subagent_cap_breaches_count += 1; cap_breaches += 1; }
        }
    }

    let round1 = |v: f64| -> f64 { (v * 10.0).round() / 10.0 };
    let shell_pct = if total_tool_calls > 0 { round1(((total_shell_calls as f64) / (total_tool_calls as f64)) * 100.0) } else { 0.0 };
    let err_pct = if total_planner_steps > 0 { round1(((total_error_steps as f64) / (total_planner_steps as f64)) * 100.0) } else { 0.0 };
    let main_avg = if main_sessions_count > 0 { round1(main_steps_per_turn_sum / (main_sessions_count as f64)) } else { 0.0 };
    let sub_avg = if subagent_runs_count > 0 { round1((subagent_steps_sum as f64) / (subagent_runs_count as f64)) } else { 0.0 };

    let grade = if sessions_scanned == 0 {
        "NO_DATA".to_string()
    } else if shell_pct >= target_shell_pct && sub_avg <= (subagent_step_cap as f64) && cap_breaches == 0 && err_pct <= 10.0 {
        "OPTIMAL".to_string()
    } else if shell_pct < 45.0 || sub_avg > 20.0 || err_pct > 25.0 || (cap_breaches > 0 && err_pct > 10.0) {
        "STEP_BLOAT_ALERT".to_string()
    } else {
        "NEEDS_BATCHING".to_string()
    };

    let data_ok = sessions_scanned > 0 && malformed_lines == 0 && truncated_sessions == 0;
    let policy_ok = data_ok && grade != "STEP_BLOAT_ALERT";
    let wire = format!(
        "@STEP_ECONOMICS/1[rule=R132|engine=kintsugi-rs|grade={grade}|sessions={sessions_scanned}|shell_pct={shell_pct:.1}|sub_avg_steps={sub_avg:.1}|breaches={subagent_cap_breaches_count}|err_pct={err_pct:.1}|caps=sub{subagent_step_cap},task{task_step_cap}]"
    );

    StepAuditReport {
        ok: data_ok, data_ok, policy_ok, target: target_label.to_string(), explicit_manifest_sha256, grade,
        candidate_files, parsed_files, malformed_lines, truncated_sessions, sessions_scanned,
        main_sessions_count, subagent_runs_count, total_planner_steps, total_tool_calls,
        total_shell_calls, total_error_steps, overall_shell_call_ratio_pct: shell_pct,
        overall_error_step_ratio_pct: err_pct, main_avg_steps_per_turn: main_avg,
        subagent_avg_steps: sub_avg, subagent_max_steps, subagent_cap_breaches_count, cap_breaches,
        subagent_step_cap, task_step_cap, target_shell_pct, elapsed_ms: (t0.elapsed().as_micros() as f64) / 1000.0, wire,
    }
}

pub fn audit_step_economics_path(
    target: &Path,
    max_sessions: usize,
    subagent_step_cap: usize,
    task_step_cap: usize,
    target_shell_pct: f64,
) -> StepAuditReport {
    let files = discover_transcripts_for_step_audit(target, max_sessions);
    audit_step_economics_with_label(&target.display().to_string(), &files, subagent_step_cap, task_step_cap, target_shell_pct)
}

#[inline]
fn fmt_f64_1(v: f64) -> String {
    format!("{:.1}", if v.is_finite() { v } else { 0.0 })
}

pub fn render_step_audit_json(rep: &StepAuditReport) -> String {
    let targets_json = JsonObj::with_capacity(160)
        .raw("shell_batch_target_pct", &fmt_f64_1(rep.target_shell_pct))
        .usize("subagent_step_cap", rep.subagent_step_cap)
        .usize("task_step_cap", rep.task_step_cap)
        .usize("auto_split_min_subtasks", 3)
        .usize("auto_split_min_est_seconds", 120)
        .finish();

    JsonObj::with_capacity(860)
        .bool("ok", rep.ok).bool("data_ok", rep.data_ok).bool("policy_ok", rep.policy_ok)
        .str("rule_id", "R132").str("protocol", "@STEP_ECONOMICS/1")
        .str("engine", "kintsugi-rs").str("engine_version", ENGINE_VERSION)
        .str("target", &rep.target).str("explicit_manifest_sha256", &rep.explicit_manifest_sha256)
        .str("grade", &rep.grade).str("wire", &rep.wire).f64_3("elapsed_ms", rep.elapsed_ms)
        .usize("candidate_files", rep.candidate_files).usize("parsed_files", rep.parsed_files)
        .usize("malformed_lines", rep.malformed_lines).usize("truncated_sessions", rep.truncated_sessions)
        .usize("sessions_scanned", rep.sessions_scanned).usize("main_sessions_count", rep.main_sessions_count)
        .usize("subagent_runs_count", rep.subagent_runs_count).usize("total_planner_steps", rep.total_planner_steps)
        .usize("total_tool_calls", rep.total_tool_calls).usize("total_shell_calls", rep.total_shell_calls)
        .usize("total_error_steps", rep.total_error_steps)
        .raw("overall_shell_call_ratio_pct", &fmt_f64_1(rep.overall_shell_call_ratio_pct))
        .raw("overall_error_step_ratio_pct", &fmt_f64_1(rep.overall_error_step_ratio_pct))
        .raw("main_avg_steps_per_turn", &fmt_f64_1(rep.main_avg_steps_per_turn))
        .raw("subagent_avg_steps", &fmt_f64_1(rep.subagent_avg_steps))
        .usize("subagent_max_steps", rep.subagent_max_steps)
        .usize("subagent_cap_breaches_count", rep.subagent_cap_breaches_count)
        .usize("cap_breaches", rep.cap_breaches).raw("targets", &targets_json)
        .finish()
}

#[derive(Debug, Clone)]
pub struct SwarmPlanConfig {
    pub subscription_tier: String,
    pub model: String,
    pub max_parallel_subagents: usize,
    pub auto_split_min_subtasks: usize,
    pub auto_split_min_est_seconds: usize,
    pub step_budget_subagent: usize,
    pub step_budget_task: usize,
    pub shell_batch_target_pct: usize,
    pub forbid: String,
    pub council_cowork: String,
}

impl Default for SwarmPlanConfig {
    fn default() -> Self {
        Self {
            subscription_tier: "UNLIMITED_LOCAL".to_string(),
            model: "FRONTIER_HIGH".to_string(),
            max_parallel_subagents: 8,
            auto_split_min_subtasks: 3,
            auto_split_min_est_seconds: 120,
            step_budget_subagent: 12,
            step_budget_task: 25,
            shell_batch_target_pct: 60,
            forbid: "flash,flash_lite".to_string(),
            council_cowork: "MANDATORY".to_string(),
        }
    }
}

pub fn render_swarm_plan_json(task_desc: &str) -> String {
    render_swarm_plan_json_with_config(task_desc, &SwarmPlanConfig::default())
}

pub fn render_swarm_plan_json_with_config(task_desc: &str, config: &SwarmPlanConfig) -> String {
    let trimmed = task_desc.trim();
    let clean = if trimmed.is_empty() { "multi-workstream task" } else { trimmed };
    let roles = JsonArr::with_capacity(256)
        .str("Frontier High Recon Scout (research/inherit)")
        .str("Frontier High Patch Engineer A (self/inherit)")
        .str("Frontier High Test & PR Engineer B (self/inherit)")
        .str("Dual Agent Council Co-Worker (Tier-2 Free + Tier-1 Paid)");
    let wire = format!(
        "@SWARM_DISPATCH/1|plan={}|max_subagents={}|auto_split_ge={}_indep_or_{}s|step_cap=sub{},task{}|shell>={}%|subagent_model={}|forbid={}|council_cowork={}",
        config.subscription_tier,
        config.max_parallel_subagents,
        config.auto_split_min_subtasks,
        config.auto_split_min_est_seconds,
        config.step_budget_subagent,
        config.step_budget_task,
        config.shell_batch_target_pct,
        config.model,
        config.forbid,
        config.council_cowork,
    );
    let model_lock = format!(
        "{} (Model='inherit' | 'pro' ONLY; FORBID {})",
        config.model, config.forbid
    );

    JsonObj::with_capacity(768)
        .bool("ok", true).str("rule", "R131").str("step_economics_rule", "R132")
        .str("protocol", "@SWARM_DISPATCH/1").str("engine", "kintsugi-rs").str("engine_version", ENGINE_VERSION)
        .str("wire", &wire)
        .str("task_desc", clean).str("subscription_tier", &config.subscription_tier)
        .str("subagent_model_lock", &model_lock)
        .usize("max_parallel_subagents", config.max_parallel_subagents)
        .usize("auto_split_min_subtasks", config.auto_split_min_subtasks)
        .usize("auto_split_min_est_seconds", config.auto_split_min_est_seconds)
        .usize("step_budget_subagent", config.step_budget_subagent)
        .usize("step_budget_task", config.step_budget_task)
        .usize("shell_batch_target_pct", config.shell_batch_target_pct)
        .arr("roles", roles)
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_line_reader_manifest_sha256_and_policy_grades() {
        let base = std::env::temp_dir().join(format!(
            "kintsugi_step_v3_{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&base).unwrap();

        let t1 = base.join("session_a.jsonl");
        let over_line = "x".repeat(MAX_TRANSCRIPT_LINE_BYTES + 4096);
        fs::write(
            &t1,
            format!(
                "{{\"type\":\"USER_INPUT\",\"content\":\"hi\"}}\n\
                 {{\"type\":\"PLANNER_RESPONSE\",\"status\":\"DONE\",\"tool_calls\":[{{\"name\":\"run_command\"}}]}}\n\
                 {over_line}\n"
            ),
        )
        .unwrap();
        let rep1 = AuditStepEconomicsWithFiles::new(vec![t1.clone()]).run();
        let rep2 = audit_step_economics_files(&[t1], 12, 25, 60.0);
        assert!(!rep1.ok && !rep1.data_ok && !rep1.policy_ok && rep1.grade == "OPTIMAL" && rep1.truncated_sessions == 1 && rep1.malformed_lines == 1);
        assert_eq!(rep1.explicit_manifest_sha256, rep2.explicit_manifest_sha256);
        assert_eq!(rep1.explicit_manifest_sha256.len(), 64);
        assert!(parse_json_value(&render_step_audit_json(&rep1)).is_ok());

        let changed = base.join("changed.jsonl");
        fs::write(&changed, b"{\"type\":\"PLANNER_RESPONSE\",\"status\":\"DONE\"}\n").unwrap();
        let before = audit_step_economics_files(&[changed.clone()], 12, 25, 60.0);
        fs::write(&changed, b"{\"type\":\"PLANNER_RESPONSE\",\"status\":\"FAIL\"}\n").unwrap();
        let after = audit_step_economics_files(&[changed.clone()], 12, 25, 60.0);
        assert_ne!(before.explicit_manifest_sha256, after.explicit_manifest_sha256);

        let user_error = base.join("user_error.jsonl");
        fs::write(
            &user_error,
            b"{\"type\":\"USER_INPUT\",\"status\":\"ERROR\"}\n\
              {\"type\":\"PLANNER_RESPONSE\",\"status\":\"DONE\"}\n",
        )
        .unwrap();
        let error_report = audit_step_economics_files(&[user_error], 12, 25, 60.0);
        assert!(error_report.overall_error_step_ratio_pct <= 100.0);
        assert_eq!(error_report.overall_error_step_ratio_pct, 0.0);

        let empty = base.join("empty.jsonl");
        fs::write(&empty, b"").unwrap();
        assert_eq!(
            audit_step_economics_files(&[empty], 12, 25, 60.0).grade,
            "NO_DATA"
        );

        let batching = base.join("batching.jsonl");
        fs::write(
            &batching,
            b"{\"type\":\"USER_INPUT\"}\n\
              {\"type\":\"PLANNER_RESPONSE\",\"tool_calls\":[{\"name\":\"run_command\"},{\"name\":\"read_file\"}]}\n",
        )
        .unwrap();
        let batching_report = audit_step_economics_files(&[batching], 12, 25, 60.0);
        assert_eq!(batching_report.grade, "NEEDS_BATCHING");

        let bloat = base.join("bloat.jsonl");
        fs::write(
            &bloat,
            b"{\"type\":\"USER_INPUT\"}\n\
              {\"type\":\"PLANNER_RESPONSE\",\"status\":\"ERROR\"}\n",
        )
        .unwrap();
        let bloat_report = audit_step_economics_files(&[bloat], 12, 25, 60.0);
        assert_eq!(bloat_report.grade, "STEP_BLOAT_ALERT");

        let capped_a = base.join("capped_a.jsonl");
        let capped_b = base.join("capped_b.jsonl");
        let capped_c = base.join("capped_c.jsonl");
        let capped_d = base.join("capped_d.jsonl");
        let capped_e = base.join("capped_e.jsonl");
        let capped_len = MAX_TRANSCRIPT_FILE_BYTES;
        let capped_file = fs::File::create(&capped_a).unwrap();
        capped_file.set_len(capped_len).unwrap();
        fs::hard_link(&capped_a, &capped_b).unwrap();
        fs::hard_link(&capped_a, &capped_c).unwrap();
        fs::hard_link(&capped_a, &capped_d).unwrap();
        fs::hard_link(&capped_a, &capped_e).unwrap();
        let capped_report = audit_step_economics_files(
            &[capped_a, capped_b, capped_c, capped_d, capped_e],
            12,
            25,
            60.0,
        );
        assert!(capped_report.truncated_sessions > 0);
        assert!(!capped_report.data_ok);

        let _ = fs::remove_dir_all(&base);
    }
}
