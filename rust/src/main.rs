//! `kintsugi-rs` — Modular Native Rust CLI entrypoint (Exit matrix: `0` pass, `1` violation,
//! `2` CLI/config/I/O error, `3` `INTERNAL_ENGINE_ERROR` panic guard).

mod cli;
mod cli_bench;

use std::any::Any;
use std::env;
use std::panic::catch_unwind;

use kintsugi_core::io_json::{write_stdout_ln, ENGINE_VERSION};

use crate::cli::audit_cmds::{
    run_capsule_cmd, run_compress_cmd, run_context_cmd, run_creed_cmd, run_hook_cmd,
    run_lexicon_cmd, run_memories_verify_cmd, run_s3_audit_cmd, run_step_audit_cmd,
    run_swarm_plan_cmd, run_task_pack_cmd, run_telemetry_cmd,
};
use crate::cli::rule_kml_cmds::{
    run_kml_cmd, run_rule_ir_check_cmd, run_rule_ir_eval_cmd, run_scan_bytes_cmd,
};
use crate::cli::scan_gate::{run_gate_cmd, run_scan_cmd};
use crate::cli::{emit_cli_error_json, print_help};

fn panic_payload_str(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&'static str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("Unexpected internal engine panic")
}

fn dispatch_cli() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        print_help();
        return;
    }
    if matches!(args[0].as_str(), "-V" | "--version" | "version") {
        write_stdout_ln(&format!("kintsugi-rs {ENGINE_VERSION}"));
        return;
    }

    match args[0].as_str() {
        "scan" => run_scan_cmd(&args),
        "gate" => run_gate_cmd(&args),
        "s3-audit" => run_s3_audit_cmd(&args),
        "memories-verify" => run_memories_verify_cmd(&args),
        "creed" => run_creed_cmd(&args),
        "swarm-plan" => run_swarm_plan_cmd(&args),
        "step-audit" => run_step_audit_cmd(&args),
        "hook" => run_hook_cmd(&args),
        "capsule" => run_capsule_cmd(&args),
        "context" => run_context_cmd(&args),
        "task-pack" => run_task_pack_cmd(&args),
        "lexicon" => run_lexicon_cmd(&args),
        "telemetry" => run_telemetry_cmd(&args),
        "kml" => run_kml_cmd(&args),
        "compress" => run_compress_cmd(&args),
        "rule-ir-check" => run_rule_ir_check_cmd(&args),
        "rule-ir-eval" => run_rule_ir_eval_cmd(&args),
        "scan-bytes" => run_scan_bytes_cmd(&args),
        "bench" => cli_bench::run_core_bench(),
        "logforge-bench" => cli_bench::run_logforge_bench_cmd(&args),
        "sha256-bench" => cli_bench::run_sha256_bench_cmd(&args),
        "scan-bench" => cli_bench::run_scan_bench_cmd(&args),
        "e2e-bench" => cli_bench::run_e2e_bench_cmd(&args),
        unknown => emit_cli_error_json(
            "UNKNOWN_SUBCOMMAND",
            &format!("Unknown subcommand '{unknown}' (run 'kintsugi-rs --help' for usage)"),
            2,
        ),
    }
}

fn main() {
    if let Err(payload) = catch_unwind(dispatch_cli) {
        emit_cli_error_json("INTERNAL_ENGINE_ERROR", panic_payload_str(payload.as_ref()), 3);
    }
}
