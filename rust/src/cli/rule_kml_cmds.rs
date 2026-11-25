//! `@KML/1`, `RuleIR/1`, and zero-alloc SIMD `scan-bytes` subcommands (`rust/src/cli/rule_kml_cmds.rs`).

#[cfg(feature = "logforge")]
use std::fmt::Write as FmtWrite;
#[cfg(feature = "logforge")]
use std::io::{self, Read};
use std::path::Path;
use std::process;
#[cfg(feature = "logforge")]
use std::time::Instant;

#[cfg(feature = "logforge")]
use kintsugi_core::io_json::{json_escape_into, read_regular_bytes_fd_verified, write_stdout_str};
#[cfg(feature = "rule-ir")]
use kintsugi_core::io_json::{read_regular_file_fd_verified, read_stdin_checked};
use kintsugi_core::io_json::{write_stdout_ln, JsonObj, ENGINE_VERSION};
#[cfg(feature = "logforge")]
use kintsugi_core::kernels::active_simd_backend;
use kintsugi_core::kml::{inspect_kml_corpus_file, ALLOWED_PUBLIC_EVOLUTION_REPO};

use super::{emit_cli_error_json, parse_delim_byte, reject_unknown_flag, ArgCursor, CliToken};

#[cfg(feature = "logforge")]
const MAX_SCAN_BYTES_INPUT: usize = 64 * 1024 * 1024;

#[cfg(feature = "rule-ir")]
fn read_source_text(src: &str) -> String {
    if src == "-" {
        read_stdin_checked().unwrap_or_else(|msg| emit_cli_error_json("STDIN_IO_ERROR", &msg, 2))
    } else {
        read_regular_file_fd_verified(Path::new(src), kintsugi_core::MAX_SOURCE_FILE_BYTES)
            .unwrap_or_else(|e| emit_cli_error_json("IO_ERROR", &e, 2))
    }
}

fn decode_hex_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let clean = hex.trim();
    if clean.len() % 2 != 0 {
        return Err(format!("Hex pattern must have even length: '{clean}'"));
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    for chunk in clean.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
        out.push(u8::from_str_radix(pair, 16).map_err(|e| format!("Invalid hex byte '{pair}': {e}"))?);
    }
    Ok(out)
}

#[cfg(feature = "logforge")]
#[inline]
fn write_opt_json_str(out: &mut String, val: Option<&str>) {
    match val {
        Some(s) => { out.push('"'); json_escape_into(s, out); out.push('"'); }
        None => out.push_str("null"),
    }
}

pub fn run_kml_cmd(args: &[String]) {
    let mut kml_path = ".kintsugi/scars.kml";
    let mut cur = ArgCursor::for_subcommand(args);
    while let Some(tok) = cur.next_item() {
        match tok {
            CliToken::Positional(p) => kml_path = p,
            CliToken::Flag(other) => reject_unknown_flag(other),
        }
    }

    match inspect_kml_corpus_file(Path::new(kml_path)) {
        Ok(rep) => {
            let out = JsonObj::with_capacity(280)
                .bool("ok", rep.quarantined_records == 0)
                .str("schema_version", ENGINE_VERSION)
                .str("engine", "kintsugi-rs")
                .str("protocol", "@KML/1.0")
                .str("path", kml_path)
                .usize("total_records", rep.total_records)
                .usize("verified_records", rep.verified_records)
                .usize("quarantined_records", rep.quarantined_records)
                .u64("elapsed_us", rep.elapsed_micros as u64)
                .f64_3("elapsed_ms", (rep.elapsed_micros as f64) / 1000.0)
                .usize("kml_bytes", rep.kml_bytes)
                .usize("estimated_tokens", rep.estimated_tokens)
                .str("allowed_egress_repo", ALLOWED_PUBLIC_EVOLUTION_REPO)
                .finish();
            write_stdout_ln(&out);
            if rep.quarantined_records > 0 { process::exit(1); }
        }
        Err(err) => emit_cli_error_json("IO_ERROR", &err, 2),
    }
}

pub fn run_rule_ir_check_cmd(args: &[String]) {
    let (mut src_arg, mut strict_hash) = ("-", false);
    let mut cur = ArgCursor::for_subcommand(args);
    while let Some(tok) = cur.next_item() {
        match tok {
            CliToken::Positional(p) => src_arg = p,
            CliToken::Flag("--strict-hash") => strict_hash = true,
            CliToken::Flag(other) => reject_unknown_flag(other),
        }
    }

    #[cfg(feature = "rule-ir")]
    {
        let raw = read_source_text(src_arg);
        let res = if strict_hash {
            kintsugi_core::rule_ir::validate_rule_ir_json_strict(&raw)
        } else {
            kintsugi_core::rule_ir::validate_rule_ir_json(&raw)
        };
        match res {
            Ok(out) => write_stdout_ln(&out),
            Err(err) => emit_cli_error_json("RULE_IR_INVALID", &err, 1),
        }
    }
    #[cfg(not(feature = "rule-ir"))]
    {
        let _ = (src_arg, strict_hash);
        emit_cli_error_json("FEATURE_DISABLED", "Subcommand 'rule-ir-check' requires Cargo feature 'rule-ir'", 2);
    }
}

pub fn run_rule_ir_eval_cmd(args: &[String]) {
    let (mut rule_arg, mut code_arg, mut lang) = (None, "-", "python");
    let mut cur = ArgCursor::for_subcommand(args);
    while let Some(tok) = cur.next_item() {
        match tok {
            CliToken::Positional(p) => code_arg = p,
            CliToken::Flag("--rule") => rule_arg = Some(cur.require_value("--rule")),
            CliToken::Flag("--lang") => lang = cur.require_value("--lang"),
            CliToken::Flag(other) => reject_unknown_flag(other),
        }
    }
    let Some(rule_src) = rule_arg else {
        emit_cli_error_json("MISSING_RULE_OPTION", "Missing required option '--rule'", 2);
    };
    if rule_src == "-" && code_arg == "-" {
        emit_cli_error_json("CONFLICTING_STDIN", "Cannot read both '--rule -' and code '-' from stdin", 2);
    }

    #[cfg(feature = "rule-ir")]
    {
        let (rule_raw, code_raw) = (read_source_text(rule_src), read_source_text(code_arg));
        match kintsugi_core::rule_ir::evaluate_rule_ir_json(&rule_raw, &code_raw, lang) {
            Ok(out) => write_stdout_ln(&out),
            Err(err) => emit_cli_error_json("RULE_IR_INVALID", &err, 1),
        }
    }
    #[cfg(not(feature = "rule-ir"))]
    {
        let _ = (rule_src, code_arg, lang);
        emit_cli_error_json("FEATURE_DISABLED", "Subcommand 'rule-ir-eval' requires Cargo feature 'rule-ir'", 2);
    }
}

pub fn run_scan_bytes_cmd(args: &[String]) {
    let (mut src_arg, mut delim, mut pattern) = ("-", b'\n', None);
    let (mut disable_simd, mut normalize, mut format) = (false, false, "json");
    let mut cur = ArgCursor::for_subcommand(args);
    while let Some(tok) = cur.next_item() {
        match tok {
            CliToken::Positional(p) => src_arg = p,
            CliToken::Flag("--delim") => {
                delim = parse_delim_byte(cur.require_value("--delim"))
                    .unwrap_or_else(|e| emit_cli_error_json("INVALID_DELIM", &e, 2));
            }
            CliToken::Flag("--pattern") => pattern = Some(cur.require_value("--pattern").as_bytes().to_vec()),
            CliToken::Flag("--pattern-hex") => {
                pattern = Some(
                    decode_hex_bytes(cur.require_value("--pattern-hex"))
                        .unwrap_or_else(|e| emit_cli_error_json("INVALID_HEX_PATTERN", &e, 2)),
                );
            }
            CliToken::Flag("--disable-simd") => disable_simd = true,
            CliToken::Flag("--normalize") => normalize = true,
            CliToken::Flag("--format") => format = cur.parse_format("--format", &["json", "offsets"]),
            CliToken::Flag(other) => reject_unknown_flag(other),
        }
    }

    #[cfg(feature = "logforge")]
    {
        use kintsugi_core::kernels::{normalize_log_records, scan_delimiters, scan_multibyte_delimiters};
        let raw_bytes = if src_arg == "-" {
            let mut buf = Vec::new();
            io::stdin()
                .lock()
                .take((MAX_SCAN_BYTES_INPUT as u64) + 1)
                .read_to_end(&mut buf)
                .unwrap_or_else(|e| emit_cli_error_json("STDIN_IO_ERROR", &e.to_string(), 2));
            if buf.len() > MAX_SCAN_BYTES_INPUT {
                emit_cli_error_json("STDIN_IO_ERROR", "scan-bytes stdin exceeds 64 MiB cap", 2);
            }
            buf
        } else {
            read_regular_bytes_fd_verified(Path::new(src_arg), MAX_SCAN_BYTES_INPUT)
                .unwrap_or_else(|e| emit_cli_error_json("IO_ERROR", &e, 2))
        };

        let t0 = Instant::now();
        let backend = active_simd_backend(disable_simd);
        let offsets = match pattern {
            Some(ref pat) => scan_multibyte_delimiters(&raw_bytes, pat, disable_simd),
            None => scan_delimiters(&raw_bytes, delim, disable_simd),
        };
        let elapsed_us = (t0.elapsed().as_nanos() as f64) / 1000.0;

        if format == "offsets" {
            let mut out = String::with_capacity(offsets.len().saturating_mul(10));
            for &off in &offsets { let _ = writeln!(&mut out, "{off}"); }
            if !out.is_empty() { write_stdout_str(&out); }
        } else {
            let mut off_raw = String::with_capacity(offsets.len().saturating_mul(10).saturating_add(2));
            off_raw.push('[');
            for (idx, &off) in offsets.iter().enumerate() {
                if idx > 0 { off_raw.push(','); }
                let _ = write!(&mut off_raw, "{off}");
            }
            off_raw.push(']');

            let mut obj = JsonObj::with_capacity(256 + off_raw.len())
                .bool("ok", true)
                .str("schema_version", "1.0")
                .str("tool", "LogForge")
                .str("backend", backend)
                .bool("disable_simd", disable_simd)
                .usize("delim", delim as usize)
                .usize("multibyte_pattern_len", pattern.as_ref().map(|p| p.len()).unwrap_or(1))
                .usize("input_bytes", raw_bytes.len())
                .usize("delimiter_count", offsets.len())
                .f64_3("elapsed_us", elapsed_us)
                .raw("offsets", &off_raw);
            if normalize && pattern.is_none() {
                let evs = normalize_log_records(&raw_bytes, delim, disable_simd);
                let mut ev_raw = String::with_capacity(evs.len().saturating_mul(160).saturating_add(2));
                ev_raw.push('[');
                for (idx, ev) in evs.iter().enumerate() {
                    if idx > 0 { ev_raw.push(','); }
                    let _ = write!(
                        &mut ev_raw,
                        "{{\"record_index\":{},\"byte_offset\":{},\"byte_len\":{},\"format\":\"{}\",\"timestamp_utc\":",
                        ev.record_index, ev.byte_offset, ev.byte_len, ev.format
                    );
                    write_opt_json_str(&mut ev_raw, ev.timestamp_utc.as_deref());
                    ev_raw.push_str(",\"timestamp_raw\":");
                    write_opt_json_str(&mut ev_raw, ev.timestamp_raw.as_deref());
                    ev_raw.push_str(",\"level\":");
                    write_opt_json_str(&mut ev_raw, ev.level.as_deref());
                    ev_raw.push_str(",\"message\":");
                    write_opt_json_str(&mut ev_raw, ev.message.as_deref());
                    ev_raw.push_str(",\"raw_preserved\":\"");
                    json_escape_into(&ev.raw_preserved, &mut ev_raw);
                    ev_raw.push_str("\"}");
                }
                ev_raw.push(']');
                obj = obj.raw("events", &ev_raw);
            }
            write_stdout_ln(&obj.finish());
        }
    }
    #[cfg(not(feature = "logforge"))]
    {
        let _ = (src_arg, delim, pattern, disable_simd, normalize, format);
        emit_cli_error_json("FEATURE_DISABLED", "Subcommand 'scan-bytes' requires Cargo feature 'logforge'", 2);
    }
}
