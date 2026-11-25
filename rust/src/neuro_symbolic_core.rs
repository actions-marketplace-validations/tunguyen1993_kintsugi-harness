//! Modular Neuro-Symbolic `@CT2` Lab CLI Dispatcher (`rust-neuro-symbolic-core`).
//! Compile: `cargo build --release --features lab-tools --bin rust-neuro-symbolic-core`

#[cfg(not(feature = "audit"))]
fn main() {
    let payload = kintsugi_core::io_json::JsonObj::new()
        .bool("ok", false)
        .str("code", "FEATURE_DISABLED")
        .str("error", "Binary 'rust-neuro-symbolic-core' requires Cargo feature 'audit'")
        .finish();
    kintsugi_core::io_json::write_stderr_safe(&payload);
    std::process::exit(2);
}

#[cfg(feature = "audit")]
#[path = "lab/mod.rs"]
mod lab;

#[cfg(feature = "audit")]
fn main() {
    use std::path::{Path, PathBuf};
    use kintsugi_core::io_json::{write_stderr_safe, write_stdout_ln};

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        write_stderr_safe("Usage: rust_neuro_symbolic_core <index|gate|inspect-fn|extract-labs|synthesize-patch|whitehat-solve|swarm-bft> <target_path> [...]");
        std::process::exit(2);
    }
    let target = Path::new(&args[2]);
    match args[1].as_str() {
        "index" => write_stdout_ln(&lab::index::render_index_json(target, args.get(3).and_then(|s| s.parse().ok()).unwrap_or(25))),
        "gate" => write_stdout_ln(&lab::index::render_gate_json(
            target, args.get(3).map_or("", String::as_str), args.get(4).map_or("", String::as_str),
            args.get(5).map_or("", String::as_str), args.get(6).map_or("NONE:S0", String::as_str),
        )),
        "inspect-fn" => write_stdout_ln(&lab::index::render_inspect_fn_json(target, args.get(3).map_or("", String::as_str))),
        "synthesize-patch" => write_stdout_ln(&lab::patch_sim::render_synthesize_patch_json(target, args.get(3).map_or("", String::as_str))),
        "whitehat-solve" => write_stdout_ln(&lab::swarm::render_whitehat_solve_json(target)),
        "swarm-bft" => write_stdout_ln(&lab::swarm::render_swarm_bft_json(
            target, args.get(3).is_some_and(|s| matches!(s.as_str(), "byzantine" | "--byzantine-test" | "1")),
        )),
        "extract-labs" => {
            let out_p = args.get(3).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("./kintsugi_labs_train.jsonl"));
            lab::cmd_extract_labs(target, &out_p);
        }
        other => {
            write_stderr_safe(&format!("Unknown command: {other}"));
            std::process::exit(2);
        }
    }
}

#[cfg(all(test, feature = "audit"))]
mod tests {
    use super::lab::{index::*, patch_sim::*, swarm::*};
    use kintsugi_core::audit::ct2_seams::grade_transform_line;
    use kintsugi_core::io_json::{fnv1a_64, FNV1A_64_INIT};
    use kintsugi_core::parse_json_value;
    use std::fs;

    #[test]
    fn fnv1a_64_and_ct2_grading_are_deterministic() {
        assert_eq!(fnv1a_64(b"kintsugi_ct2", FNV1A_64_INIT), fnv1a_64(b"kintsugi_ct2", FNV1A_64_INIT));
        assert_eq!(grade_transform_line("shell=False", "CMD_EXEC").unwrap().1, "S3");
        assert_eq!(grade_transform_line("if \"127.0.0.1\" in target_url:", "SSRF_CRLF_CHAIN").unwrap().1, "S1");
    }

    #[test]
    fn all_json_renderers_produce_dom_valid_json() {
        let base = std::env::temp_dir().join(format!("rns_json_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        fs::write(base.join("sample\"quote.py"), "import os\ndef run_job(cmd):\n    return os.system(cmd)\n").unwrap();

        for rendered in [
            render_index_json(&base, 25),
            render_gate_json(&base, "run_job", "sample\"quote.py:3", "cmd", "NONE:S0"),
            render_inspect_fn_json(&base, "run_job"),
            render_inspect_fn_json(&base, "missing_fn"),
            render_synthesize_patch_json(&base, "sample\"quote.py:3"),
            render_whitehat_solve_json(&base),
            render_swarm_bft_json(&base, true),
        ] {
            assert!(parse_json_value(&rendered).is_ok(), "Invalid JSON: {rendered}");
        }
        let (s3_cmd, _) = s3_patch_spec("CMD_EXEC");
        let (pre, post, grade, ok) = verify_patch_regression("os.system(cmd)", s3_cmd, "CMD_EXEC", "job.py:4");
        assert!(pre >= 1 && post == 0 && grade.ends_with(":S3") && ok);
        let _ = fs::remove_dir_all(&base);
    }
}
