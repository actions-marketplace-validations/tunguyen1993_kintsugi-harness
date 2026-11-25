//! Shared typed `ArgCursor` CLI parser, structured JSON error emitter, and help text (`kintsugi-rs`).

pub mod audit_cmds;
pub mod rule_kml_cmds;
pub mod scan_gate;

use std::process;

use kintsugi_core::io_json::{write_stdout_ln, JsonObj, ENGINE_VERSION};
use kintsugi_core::model::Severity;

/// Classified CLI token yielded by [`ArgCursor::next_item`], handling `--` double-dash in one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliToken<'a> {
    Positional(&'a str),
    Flag(&'a str),
}

impl<'a> CliToken<'a> {
    #[inline]
    pub fn as_str(self) -> &'a str {
        match self {
            CliToken::Positional(s) | CliToken::Flag(s) => s,
        }
    }
}

/// Zero-allocation typed cursor over CLI arguments with unified `--` double-dash handling.
pub struct ArgCursor<'a> {
    args: &'a [String],
    idx: usize,
    after_double_dash: bool,
}

impl<'a> ArgCursor<'a> {
    #[inline]
    pub fn new(args: &'a [String]) -> Self {
        Self { args, idx: 0, after_double_dash: false }
    }

    #[inline]
    pub fn for_subcommand(args: &'a [String]) -> Self {
        Self::new(args.get(1..).unwrap_or(&[]))
    }

    pub fn next_item(&mut self) -> Option<CliToken<'a>> {
        while self.idx < self.args.len() {
            let raw = self.args[self.idx].as_str();
            self.idx += 1;
            if self.after_double_dash {
                return Some(CliToken::Positional(raw));
            }
            if raw == "--" {
                self.after_double_dash = true;
                continue;
            }
            if raw.starts_with('-') && raw != "-" {
                return Some(CliToken::Flag(raw));
            }
            return Some(CliToken::Positional(raw));
        }
        None
    }

    pub fn require_value(&mut self, flag: &str) -> &'a str {
        if self.idx >= self.args.len() {
            emit_cli_error_json("MISSING_OPTION_VALUE", &format!("Missing value for option '{flag}'"), 2);
        }
        let val = self.args[self.idx].as_str();
        self.idx += 1;
        val
    }

    pub fn parse_usize(&mut self, flag: &str) -> usize {
        let raw = self.require_value(flag);
        raw.parse::<usize>().unwrap_or_else(|_| {
            emit_cli_error_json(
                "INVALID_USIZE",
                &format!("Invalid {flag} value '{raw}' (expected non-negative integer)"),
                2,
            )
        })
    }

    pub fn parse_u64(&mut self, flag: &str) -> u64 {
        let raw = self.require_value(flag);
        raw.parse::<u64>().unwrap_or_else(|_| {
            emit_cli_error_json(
                "INVALID_U64",
                &format!("Invalid {flag} value '{raw}' (expected unsigned 64-bit integer)"),
                2,
            )
        })
    }

    pub fn parse_f64(&mut self, flag: &str) -> f64 {
        let raw = self.require_value(flag);
        match raw.parse::<f64>() {
            Ok(v) if v.is_finite() => v,
            _ => emit_cli_error_json(
                "INVALID_F64",
                &format!("Invalid {flag} value '{raw}' (expected finite number)"),
                2,
            ),
        }
    }

    pub fn parse_severity(&mut self, flag: &str) -> Severity {
        let raw = self.require_value(flag);
        parse_severity_str(flag, raw)
    }

    pub fn parse_fail_on(&mut self, flag: &str) -> Option<Severity> {
        let raw = self.require_value(flag);
        if raw.eq_ignore_ascii_case("NONE") { None } else { Some(parse_severity_str(flag, raw)) }
    }

    pub fn parse_format(&mut self, flag: &str, allowed: &[&str]) -> &'a str {
        let raw = self.require_value(flag);
        if !allowed.contains(&raw) {
            emit_cli_error_json(
                "UNSUPPORTED_FORMAT",
                &format!("Unsupported {flag} '{raw}' (expected {})", allowed.join(", ")),
                2,
            );
        }
        raw
    }
}

fn parse_severity_str(flag: &str, raw: &str) -> Severity {
    Severity::parse_strict(raw).unwrap_or_else(|| {
        emit_cli_error_json(
            "INVALID_SEVERITY",
            &format!("Invalid {flag} severity '{raw}' (expected LOW, MEDIUM, HIGH, or CRITICAL)"),
            2,
        )
    })
}

/// Emit a deterministic RFC 8259 JSON error object on `stderr` and terminate with `exit_code`.
#[cold]
pub fn emit_cli_error_json(code: &str, msg: &str, exit_code: i32) -> ! {
    let payload = JsonObj::new()
        .bool("ok", false)
        .str("schema_version", ENGINE_VERSION)
        .str("code", code)
        .str("error", msg)
        .finish();
    eprintln!("{payload}");
    process::exit(exit_code);
}

#[cold]
pub fn reject_unknown_flag(arg: &str) -> ! {
    let msg = if arg.starts_with('-') && arg != "-" {
        format!("Unknown option '{arg}'")
    } else {
        format!("Unexpected argument '{arg}'")
    };
    emit_cli_error_json("UNKNOWN_ARGUMENT", &msg, 2);
}

pub fn parse_delim_byte(spec: &str) -> Result<u8, String> {
    match spec {
        "\\n" | "\n" | "lf" | "LF" | "newline" => Ok(b'\n'),
        "\\0" | "\0" | "nul" | "NUL" | "null" => Ok(b'\0'),
        "\\r" | "\r" | "cr" | "CR" => Ok(b'\r'),
        "\\t" | "\t" | "tab" | "TAB" => Ok(b'\t'),
        _ if spec.starts_with("0x") || spec.starts_with("0X") => {
            u8::from_str_radix(&spec[2..], 16).map_err(|e| format!("Invalid hex delimiter '{spec}': {e}"))
        }
        _ if spec.len() == 1 => Ok(spec.as_bytes()[0]),
        _ => spec.parse::<u8>().map_err(|e| format!("Invalid delimiter '{spec}': {e}")),
    }
}

pub fn print_help() {
    write_stdout_ln(&format!(
        "kintsugi-rs {ENGINE_VERSION} — Native Rust @KML/1 & Grade-S3 Guardrail Engine\n\n\
         USAGE:\n\
         \x20 kintsugi-rs gate [PATH...] [--staged] [--s3] [--strict-proven] [--shadow-arm-c|--no-shadow-arm-c]\n\
         \x20                  [--rules-dir PATH] [--min-severity LEVEL] [--fail-on LEVEL|NONE]\n\
         \x20                  [--policy-file PATH] [--policy-sha256 HEX] [--max-tokens N]\n\
         \x20                  [--format compact|json|jsonl|sarif] [-- <PATH...>]\n\
         \x20 kintsugi-rs scan [PATH...] [--staged] [--shadow-arm-c|--no-shadow-arm-c] [--gate-compact]\n\
         \x20                  [--rules-dir PATH] [--format text|json|jsonl|sarif|compact]\n\
         \x20                  [--min-severity LEVEL] [--fail-on LEVEL|NONE]\n\
         \x20                  [--policy-file PATH] [--policy-sha256 HEX] [-- <PATH...>]\n\
         \x20 kintsugi-rs s3-audit [PATH...] [--strict-proven] [--format text|json] [-- <PATH...>]\n\
         \x20 kintsugi-rs memories-verify [WORKSPACE_ROOT] [--format text|json]\n\
         \x20 kintsugi-rs hook [claude-pre-tool|claude-post-read] [--block-on LEVEL] [--workspace PATH] [--exit-on-deny] [--low-tier] [--max-tokens N]\n\
         \x20 kintsugi-rs step-audit [PATH] [--max-sessions N] [--sub-cap N] [--task-cap N] [--target-shell PCT] [--allow-bloat] [--wire]\n\
         \x20 kintsugi-rs capsule <FILE_PATH> [--capsules-file PATH] [--max-capsules N] [--format compact|json]\n\
         \x20 kintsugi-rs context <FILE_PATH> [--low-tier] [--capsules-file PATH] [--max-tokens N] [--format json|compact]\n\
         \x20 kintsugi-rs task-pack <FILE_PATH...> [--low-tier|--no-low-tier] [--max-tokens N] [--format compact|json]\n\
         \x20 kintsugi-rs lexicon [FILE_PATH] [--all] [--lang LANG] [--max-entries N] [--format compact|json]\n\
         \x20 kintsugi-rs creed | swarm-plan [TASK_DESC] | compress [--kml [--lang LANG|--for-file PATH]] | kml [PATH_TO_SCARS_KML]\n\
         \x20 kintsugi-rs rule-ir-check [PATH|-] [--strict-hash]\n\
         \x20 kintsugi-rs rule-ir-eval --rule PATH|- [--lang LANG] [CODE_PATH|-]\n\
         \x20 kintsugi-rs scan-bytes [PATH|-] [--delim SPEC] [--pattern STR] [--pattern-hex HEX] [--disable-simd] [--normalize] [--format json|offsets]\n\
         \x20 kintsugi-rs e2e-bench [PATH] [--warmup N] [--iters N] [--format json|text]\n\
         \x20 kintsugi-rs bench | scan-bench [PATH] | logforge-bench [...] | sha256-bench [...]\n\n\
         BEHAVIOR & SEMANTICS:\n\
         \x20 • `gate` enables Arm C shadow AST rules by default (`--shadow-arm-c`); pass `--no-shadow-arm-c` to disable.\n\
         \x20 • `--min-severity` sets the reporting floor; `--fail-on` sets the exit-code policy threshold (`NONE` disables exit 1).\n\
         \x20 • `--strict-proven` requires proven S3 AST/confinement locks on every seam (used with `s3-audit` or `gate --s3`).\n\n\
         EXIT CODES:\n\
         \x20 0  Clean / allowed / pass\n\
         \x20 1  Security or policy violation (`scan`/`gate` >= `--fail-on`, `s3-audit` fail, `memories-verify` fail,\n\
         \x20    `step-audit` `!policy_ok`, quarantined KML, invalid RuleIR, or `hook --exit-on-deny` denied)\n\
         \x20 2  CLI usage error, invalid flag/value, config/policy failure, disabled Cargo feature, or I/O error\n\
         \x20 3  Internal engine panic guard (`INTERNAL_ENGINE_ERROR`)"
    ));
}
