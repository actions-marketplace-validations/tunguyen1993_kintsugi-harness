//! Delivery Gate Telemetry & Live 2-Strike / Dead-Scar Auto-Freeze Tracker (`rust/src/audit/delivery_telemetry.rs`).
//!
//! Honest 3-stage receipt tracking (`issued -> included_in_input -> patch_bound`) across
//! `claude_code`, `antigravity`, `local_cli`, and `cloud_sandbox` with `O_NOFOLLOW` + atomic `0o600`
//! persistence, ancestor symlink rejection, cross-process `<store>.lock` serialization,
//! and 2-strike / dead-scar auto-freeze parity with `capsules.rs`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::io_json::{read_regular_file_fd_verified, JsonArr, JsonObj, ENGINE_VERSION};
use crate::json_dom::{parse_json_value, JsonValue};

pub const DELIVERY_TELEMETRY_SCHEMA: &str = "DeliveryTelemetry/1";
pub const SUPPORTED_CLIENTS: &[&str] = &["claude_code", "antigravity", "local_cli", "cloud_sandbox"];
pub const SUPPORTED_STAGES: &[&str] = &["issued", "included_in_input", "patch_bound"];
pub const MAX_TELEMETRY_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub const GATE_3_MIN_SESSIONS: usize = 10;
pub const TWO_STRIKE_LOSS_LIMIT: u32 = 2;
pub const DEAD_SCAR_MIN_TRIALS: u32 = 30;
pub const DEAD_SCAR_MIN_WIN_PCT: u64 = 15;
const MAX_ID_LEN: usize = 256;
static TEMP_SEQ: AtomicUsize = AtomicUsize::new(0);

#[cfg(unix)]
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos", target_os = "freebsd", target_os = "dragonfly", target_os = "netbsd", target_os = "openbsd"))]
const O_NOFOLLOW_FLAG: i32 = 0x0100;
#[cfg(unix)]
#[cfg(any(target_os = "solaris", target_os = "illumos"))]
const O_NOFOLLOW_FLAG: i32 = 0x20000;
#[cfg(unix)]
#[cfg(target_os = "haiku")]
const O_NOFOLLOW_FLAG: i32 = 0x0008_0000;
#[cfg(unix)]
#[cfg(target_os = "aix")]
const O_NOFOLLOW_FLAG: i32 = 0x0100_0000;
#[cfg(unix)]
#[cfg(target_os = "nto")]
const O_NOFOLLOW_FLAG: i32 = 0o010000;
#[cfg(unix)]
#[cfg(all(any(target_os = "linux", target_os = "android"), any(target_arch = "aarch64", target_arch = "arm", target_arch = "m68k", target_arch = "powerpc", target_arch = "powerpc64")))]
const O_NOFOLLOW_FLAG: i32 = 0o100000;
#[cfg(unix)]
#[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64", target_arch = "riscv32", target_arch = "riscv64", target_arch = "s390x", target_arch = "mips", target_arch = "mips64", target_arch = "sparc", target_arch = "sparc64", target_arch = "loongarch64", target_arch = "hexagon", target_arch = "csky")))]
const O_NOFOLLOW_FLAG: i32 = 0o400000;
#[cfg(unix)]
#[cfg(all(target_os = "android", any(target_arch = "x86", target_arch = "x86_64")))]
const O_NOFOLLOW_FLAG: i32 = 0o400000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeTelemetryRecord {
    pub envelope_id: String, pub session_id: String, pub client: String, pub source_digest: String,
    pub capsule_ids: Vec<String>, pub pitfall_ids: Vec<String>, pub estimated_tokens: usize,
    pub stage: String, pub timestamp_utc: u64, pub included_in_input: bool,
    pub included_before_first_patch: bool, pub included_at_utc: Option<u64>,
    pub patch_bound: bool, pub patch_digest: String, pub passed: Option<bool>,
    pub first_patch: bool, pub patch_bound_at_utc: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EfficacyRecord {
    pub id: String, pub wins: u32, pub losses: u32, pub trials: u32,
    pub consecutive_losses: u32, pub frozen: bool, pub freeze_reason: Option<String>,
}

impl EfficacyRecord {
    pub fn new(id: String) -> Self {
        Self { id, wins: 0, losses: 0, trials: 0, consecutive_losses: 0, frozen: false, freeze_reason: None }
    }
    #[inline]
    fn dead_scar(&self) -> bool {
        self.trials >= DEAD_SCAR_MIN_TRIALS && (self.wins as u64) * 100 < (self.trials as u64) * DEAD_SCAR_MIN_WIN_PCT
    }
    #[inline]
    pub fn is_auto_frozen(&self) -> bool {
        self.frozen || self.consecutive_losses >= TWO_STRIKE_LOSS_LIMIT || self.dead_scar()
    }
    #[inline]
    pub fn effective_freeze_reason(&self) -> Option<&str> {
        if let Some(ref r) = self.freeze_reason {
            if !r.is_empty() { return Some(r.as_str()); }
        }
        if self.consecutive_losses >= TWO_STRIKE_LOSS_LIMIT { Some("two_strike_consecutive_losses") }
        else if self.dead_scar() { Some("dead_scar_low_efficacy") }
        else if self.frozen { Some("manual_or_persisted_freeze") }
        else { None }
    }
    #[inline]
    pub fn efficacy_pct(&self) -> f64 {
        if self.trials == 0 { 0.0 } else { ((self.wins as f64) * 100.0) / (self.trials as f64) }
    }
    pub fn apply_outcome(&mut self, passed: bool) -> bool {
        let was_frozen = self.is_auto_frozen();
        if was_frozen {
            if self.freeze_reason.as_deref().map_or(true, str::is_empty) {
                self.freeze_reason = self.effective_freeze_reason().map(str::to_string);
            }
            self.frozen = true;
        }
        self.trials = self.trials.saturating_add(1);
        if passed { self.wins = self.wins.saturating_add(1); self.consecutive_losses = 0; }
        else { self.losses = self.losses.saturating_add(1); self.consecutive_losses = self.consecutive_losses.saturating_add(1); }
        if !self.frozen {
            if self.consecutive_losses >= TWO_STRIKE_LOSS_LIMIT {
                self.frozen = true; self.freeze_reason = Some("two_strike_consecutive_losses".to_string());
            } else if self.dead_scar() {
                self.frozen = true; self.freeze_reason = Some("dead_scar_low_efficacy".to_string());
            }
        }
        !was_frozen && self.is_auto_frozen()
    }
}

#[derive(Debug, Default, Clone)]
struct TelemetryStore {
    updated_at_utc: u64,
    envelopes: BTreeMap<String, EnvelopeTelemetryRecord>,
    efficacy: BTreeMap<String, EfficacyRecord>,
    applied_outcomes: BTreeSet<String>,
}

#[inline]
pub fn is_supported_client(client: &str) -> bool { SUPPORTED_CLIENTS.contains(&client) }
fn now_unix_secs() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }
fn fmt_f64_4(v: f64) -> String { format!("{:.4}", if !v.is_finite() || v == 0.0 { 0.0 } else { v }) }
fn opt_u64_raw(v: Option<u64>) -> String { v.map_or_else(|| "null".to_string(), |n| n.to_string()) }
fn opt_bool_raw(v: Option<bool>) -> &'static str { match v { Some(true) => "true", Some(false) => "false", None => "null" } }

fn validate_id_token(field: &str, raw: &str, required: bool) -> Result<String, String> {
    let t = raw.trim();
    if t.is_empty() {
        return if required { Err(format!("MISSING_{}", field.to_ascii_uppercase())) } else { Ok(String::new()) };
    }
    if t.len() > MAX_ID_LEN || t.bytes().any(|b| b < 0x20 || b == 0x7f || b == b'|') {
        return Err(format!("INVALID_{}: control chars, '|', or length > {MAX_ID_LEN}", field.to_ascii_uppercase()));
    }
    Ok(t.to_string())
}

fn dedupe_ids(ids: &[String]) -> Result<Vec<String>, String> {
    let (mut seen, mut out) = (BTreeSet::new(), Vec::new());
    for raw in ids {
        let clean = validate_id_token("item_id", raw, false)?;
        if !clean.is_empty() && seen.insert(clean.clone()) { out.push(clean); }
    }
    Ok(out)
}

#[cfg(target_os = "macos")]
fn is_macos_system_root_symlink(p: &Path) -> bool {
    matches!(
        (p.to_str(), fs::read_link(p).ok().as_deref().and_then(Path::to_str)),
        (Some("/var"), Some("private/var"))
            | (Some("/tmp"), Some("private/tmp"))
            | (Some("/etc"), Some("private/etc"))
    )
}
#[cfg(not(target_os = "macos"))]
fn is_macos_system_root_symlink(_p: &Path) -> bool { false }

fn reject_symlink_if_present(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(format!("REFUSING_SYMLINK: {}", path.display())),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("STAT_ERROR on {}: {e}", path.display())),
    }
}

fn reject_symlink_ancestors(dir: &Path) -> Result<(), String> {
    let mut cur = PathBuf::new();
    for comp in dir.components() {
        cur.push(comp);
        if matches!(comp, Component::Prefix(_) | Component::CurDir) || cur.as_os_str().is_empty() {
            continue;
        }
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => {
                if !is_macos_system_root_symlink(&cur) {
                    return Err(format!("REFUSING_SYMLINK_ANCESTOR: {}", cur.display()));
                }
            }
            Ok(m) if !m.is_dir() => return Err(format!("ANCESTOR_NOT_DIR: {}", cur.display())),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("STAT_ERROR on {}: {e}", cur.display())),
        }
    }
    Ok(())
}

fn ensure_safe_parent_dir(path: &Path) -> Result<&Path, String> {
    reject_symlink_if_present(path)?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    reject_symlink_ancestors(parent)?;
    fs::create_dir_all(parent).map_err(|e| format!("CREATE_DIR_FAILED: {e}"))?;
    reject_symlink_ancestors(parent)?;
    let allow_mac_root = is_macos_system_root_symlink(parent);
    let pmeta = if allow_mac_root { fs::metadata(parent) } else { fs::symlink_metadata(parent) }
        .map_err(|e| format!("STAT_PARENT_FAILED: {e}"))?;
    if (!allow_mac_root && pmeta.file_type().is_symlink()) || !pmeta.is_dir() {
        return Err(format!("REFUSING_SYMLINK_PARENT: {}", parent.display()));
    }
    Ok(parent)
}

fn prepare_lock_path(store_path: &Path) -> Result<PathBuf, String> {
    let _ = ensure_safe_parent_dir(store_path)?;
    let mut os = store_path.as_os_str().to_os_string();
    os.push(".lock");
    let lock_path = PathBuf::from(os);
    reject_symlink_if_present(&lock_path)?;
    Ok(lock_path)
}

#[cfg(unix)]
struct StoreLockGuard { file: File }

#[cfg(unix)]
impl StoreLockGuard {
    fn acquire(store_path: &Path) -> Result<Self, String> {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;
        extern "C" { fn flock(fd: i32, operation: i32) -> i32; }
        const LOCK_EX: i32 = 2;
        let lock_path = prepare_lock_path(store_path)?;
        let file = OpenOptions::new()
            .read(true).write(true).create(true).mode(0o600).custom_flags(O_NOFOLLOW_FLAG)
            .open(&lock_path)
            .map_err(|e| format!("LOCK_OPEN_FAILED: {e}"))?;
        let fmeta = file.metadata().map_err(|e| format!("LOCK_FSTAT_FAILED: {e}"))?;
        if !fmeta.file_type().is_file() {
            return Err(format!("REFUSING_NON_REGULAR_LOCK: {}", lock_path.display()));
        }
        let fd = file.as_raw_fd();
        loop {
            // SAFETY: `fd` is a valid open file descriptor owned by `file` for the duration of `flock`.
            let rc = unsafe { flock(fd, LOCK_EX) };
            if rc == 0 { return Ok(Self { file }); }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(format!("LOCK_FLOCK_FAILED: {err}"));
            }
        }
    }
}

#[cfg(unix)]
impl Drop for StoreLockGuard {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        extern "C" { fn flock(fd: i32, operation: i32) -> i32; }
        const LOCK_UN: i32 = 8;
        let fd = self.file.as_raw_fd();
        loop {
            // SAFETY: `fd` remains valid until `self.file` drops after `Drop::drop` finishes.
            let rc = unsafe { flock(fd, LOCK_UN) };
            if rc == 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted { break; }
        }
    }
}

#[cfg(not(unix))]
struct StoreLockGuard { lock_path: PathBuf }

#[cfg(not(unix))]
impl StoreLockGuard {
    fn acquire(store_path: &Path) -> Result<Self, String> {
        let lock_path = prepare_lock_path(store_path)?;
        for _ in 0..200 {
            match OpenOptions::new().write(true).create_new(true).open(&lock_path) {
                Ok(_) => return Ok(Self { lock_path }),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    if let Ok(m) = fs::symlink_metadata(&lock_path) {
                        if m.file_type().is_symlink() {
                            return Err(format!("REFUSING_SYMLINK: {}", lock_path.display()));
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => return Err(format!("LOCK_OPEN_FAILED: {e}")),
            }
        }
        Err(format!("TELEMETRY_LOCK_TIMEOUT: {}", lock_path.display()))
    }
}

#[cfg(not(unix))]
impl Drop for StoreLockGuard {
    fn drop(&mut self) { let _ = fs::remove_file(&self.lock_path); }
}

#[cfg(unix)]
fn open_temp_nofollow_0600(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(O_NOFOLLOW_FLAG).open(path)
}
#[cfg(not(unix))]
fn open_temp_nofollow_0600(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

/// Atomically persist `bytes` to `path` via `O_CREAT | O_EXCL | O_NOFOLLOW`, `0o600`, `sync_all`, and rename.
pub fn atomic_write_file_secure(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = ensure_safe_parent_dir(path)?;
    let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("delivery_telemetry.json");
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let tmp = parent.join(format!(".{fname}.{}.{nanos}.{seq}.tmp", std::process::id()));
    let mut f = open_temp_nofollow_0600(&tmp).map_err(|e| format!("TEMP_OPEN_FAILED: {e}"))?;
    let wres: Result<(), String> = (|| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(0o600)).map_err(|e| format!("FCHMOD_0600_FAILED: {e}"))?;
        }
        f.write_all(bytes).map_err(|e| format!("WRITE_FAILED: {e}"))?;
        f.sync_all().map_err(|e| format!("FSYNC_FAILED: {e}"))
    })();
    drop(f);
    if wres.is_err() || reject_symlink_if_present(path).is_err() {
        let _ = fs::remove_file(&tmp);
        wres?;
        reject_symlink_if_present(path)?;
    }
    fs::rename(&tmp, path).map_err(|e| { let _ = fs::remove_file(&tmp); format!("ATOMIC_RENAME_FAILED: {e}") })
}

type JObj = BTreeMap<String, JsonValue>;
fn req_nonempty_str(o: &JObj, k: &str) -> Result<String, String> {
    match o.get(k) {
        Some(JsonValue::Str(s)) if !s.trim().is_empty() => Ok(s.clone()),
        Some(JsonValue::Str(_)) => Err(format!("Empty '{k}'")),
        _ => Err(format!("Missing or invalid '{k}'")),
    }
}
fn opt_str_v(o: &JObj, k: &str) -> Result<Option<String>, String> { match o.get(k) { None | Some(JsonValue::Null) => Ok(None), Some(JsonValue::Str(s)) => Ok(Some(s.clone())), _ => Err(format!("Bad str '{k}'")) } }
fn str_or_empty_v(o: &JObj, k: &str) -> Result<String, String> { match o.get(k) { None => Ok(String::new()), Some(JsonValue::Str(s)) => Ok(s.clone()), _ => Err(format!("Bad str '{k}'")) } }
fn parse_u64_str(k: &str, s: &str, ty: &str) -> Result<u64, String> {
    s.parse().map_err(|_| if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) { format!("INT_OVERFLOW: '{k}'={s}") } else { format!("Bad {ty} '{k}'") })
}
fn opt_u64_v(o: &JObj, k: &str) -> Result<Option<u64>, String> { match o.get(k) { None | Some(JsonValue::Null) => Ok(None), Some(JsonValue::Number(s)) => parse_u64_str(k, s, "u64").map(Some), _ => Err(format!("Bad u64 '{k}'")) } }
fn u64_counter_v(o: &JObj, k: &str) -> Result<u64, String> { match o.get(k) { None => Ok(0), Some(JsonValue::Number(s)) => parse_u64_str(k, s, "u64"), Some(_) => Err(format!("Bad u64 '{k}'")) } }
fn u32_counter_v(o: &JObj, k: &str) -> Result<u32, String> {
    let v = match o.get(k) { None => return Ok(0), Some(JsonValue::Number(s)) => parse_u64_str(k, s, "u32")?, Some(_) => return Err(format!("Bad u32 '{k}'")) };
    u32::try_from(v).map_err(|_| format!("INT_OVERFLOW: '{k}'={v} exceeds u32::MAX"))
}
fn usize_counter_v(o: &JObj, k: &str) -> Result<usize, String> {
    let v = match o.get(k) { None => return Ok(0), Some(JsonValue::Number(s)) => parse_u64_str(k, s, "usize")?, Some(_) => return Err(format!("Bad usize '{k}'")) };
    usize::try_from(v).map_err(|_| format!("INT_OVERFLOW: '{k}'={v} exceeds usize::MAX"))
}
fn req_bool_v(o: &JObj, k: &str) -> Result<bool, String> { match o.get(k) { None => Ok(false), Some(JsonValue::Bool(b)) => Ok(*b), _ => Err(format!("Bad bool '{k}'")) } }
fn opt_bool_v(o: &JObj, k: &str) -> Result<Option<bool>, String> { match o.get(k) { None | Some(JsonValue::Null) => Ok(None), Some(JsonValue::Bool(b)) => Ok(Some(*b)), _ => Err(format!("Bad bool '{k}'")) } }
fn str_vec_v(o: &JObj, k: &str) -> Result<Vec<String>, String> { match o.get(k) { None => Ok(Vec::new()), Some(JsonValue::Array(a)) => a.iter().map(|v| v.as_str().map(str::to_string).ok_or_else(|| format!("Non-str '{k}'"))).collect(), _ => Err(format!("Bad arr '{k}'")) } }

fn load_store(store_path: &Path) -> Result<TelemetryStore, String> {
    if let Some(p) = store_path.parent().filter(|p| !p.as_os_str().is_empty()) { reject_symlink_ancestors(p)?; }
    match fs::symlink_metadata(store_path) {
        Ok(m) if m.file_type().is_symlink() => return Err(format!("REFUSING_SYMLINK: {}", store_path.display())),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(TelemetryStore::default()),
        Err(e) => return Err(format!("STAT_ERROR: {e}")),
    }
    let raw = read_regular_file_fd_verified(store_path, MAX_TELEMETRY_FILE_BYTES)?;
    if raw.is_empty() { return Ok(TelemetryStore::default()); }
    let val = parse_json_value(raw.trim())?;
    let root = val.as_object().ok_or_else(|| "UNRECOGNIZED_TELEMETRY_STORE: root must be object".to_string())?;
    match root.get("schema") {
        Some(JsonValue::Str(s)) if s == DELIVERY_TELEMETRY_SCHEMA => {}
        Some(JsonValue::Str(s)) => return Err(format!("UNRECOGNIZED_TELEMETRY_STORE: UNSUPPORTED_SCHEMA: {s}")),
        _ => return Err("UNRECOGNIZED_TELEMETRY_STORE: missing or invalid schema".to_string()),
    }
    let updated_at_utc = match root.get("updated_at_utc") {
        None | Some(JsonValue::Null) => 0u64,
        Some(JsonValue::Number(s)) => s.parse::<u64>().map_err(|_| {
            if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) { format!("INT_OVERFLOW: 'updated_at_utc'={s}") } else { "CORRUPT_STORE: bad 'updated_at_utc'".to_string() }
        })?,
        Some(_) => return Err("CORRUPT_STORE: 'updated_at_utc' must be u64".to_string()),
    };
    let envs = match root.get("envelopes") {
        Some(JsonValue::Object(m)) => m,
        _ => return Err("UNRECOGNIZED_TELEMETRY_STORE: missing or invalid 'envelopes' object".to_string()),
    };
    let effs = match root.get("efficacy") {
        Some(JsonValue::Object(m)) => m,
        _ => return Err("UNRECOGNIZED_TELEMETRY_STORE: missing or invalid 'efficacy' object".to_string()),
    };
    let mut applied_outcomes = BTreeSet::new();
    let needs_backfill = match root.get("applied_outcomes") {
        None => true,
        Some(JsonValue::Array(arr)) => {
            for item in arr {
                let s = item.as_str().ok_or_else(|| "CORRUPT_STORE: 'applied_outcomes' items must be strings".to_string())?;
                applied_outcomes.insert(s.to_string());
            }
            false
        }
        Some(_) => return Err("CORRUPT_STORE: 'applied_outcomes' must be array".to_string()),
    };
    let mut store = TelemetryStore { updated_at_utc, applied_outcomes, ..Default::default() };
    for (k, ev) in envs {
        let o = ev.as_object().ok_or_else(|| format!("Envelope '{k}' not object"))?;
        let client = req_nonempty_str(o, "client")?;
        if !is_supported_client(&client) { return Err(format!("UNSUPPORTED_CLIENT_IN_STORE: {client}")); }
        let stage = req_nonempty_str(o, "stage")?;
        if !SUPPORTED_STAGES.contains(&stage.as_str()) { return Err(format!("UNSUPPORTED_STAGE_IN_STORE: {stage}")); }
        let _ = opt_bool_v(o, "patch_passed")?;
        store.envelopes.insert(k.clone(), EnvelopeTelemetryRecord {
            envelope_id: req_nonempty_str(o, "envelope_id")?,
            session_id: req_nonempty_str(o, "session_id")?, client,
            source_digest: str_or_empty_v(o, "source_digest")?,
            capsule_ids: str_vec_v(o, "capsule_ids")?, pitfall_ids: str_vec_v(o, "pitfall_ids")?,
            estimated_tokens: usize_counter_v(o, "estimated_tokens")?,
            stage, timestamp_utc: u64_counter_v(o, "timestamp_utc")?,
            included_in_input: req_bool_v(o, "included_in_input")?,
            included_before_first_patch: req_bool_v(o, "included_before_first_patch")?,
            included_at_utc: opt_u64_v(o, "included_at_utc")?, patch_bound: req_bool_v(o, "patch_bound")?,
            patch_digest: opt_str_v(o, "patch_digest")?.unwrap_or_default(),
            passed: opt_bool_v(o, "passed")?, first_patch: req_bool_v(o, "first_patch")?,
            patch_bound_at_utc: opt_u64_v(o, "patch_bound_at_utc")?,
        });
    }
    for (k, fv) in effs {
        let o = fv.as_object().ok_or_else(|| format!("Efficacy '{k}' not object"))?;
        let _ = u64_counter_v(o, "last_updated_utc")?;
        let id = opt_str_v(o, "id")?.filter(|s| !s.trim().is_empty()).unwrap_or_else(|| k.clone());
        store.efficacy.insert(k.clone(), EfficacyRecord {
            id,
            wins: u32_counter_v(o, "wins")?, losses: u32_counter_v(o, "losses")?,
            trials: u32_counter_v(o, "trials")?, consecutive_losses: u32_counter_v(o, "consecutive_losses")?,
            frozen: req_bool_v(o, "frozen")?, freeze_reason: opt_str_v(o, "freeze_reason")?,
        });
    }
    if needs_backfill {
        for env in store.envelopes.values() {
            if env.patch_bound && env.included_before_first_patch && !env.patch_digest.is_empty() {
                for id in env.capsule_ids.iter().chain(env.pitfall_ids.iter()) {
                    store.applied_outcomes.insert(format!("{}|{}|{}|{}", env.client, env.session_id, env.patch_digest, id));
                }
            }
        }
    }
    Ok(store)
}

fn save_store(store_path: &Path, store: &TelemetryStore) -> Result<(), String> {
    let mut envs_j = JsonObj::with_capacity(store.envelopes.len() * 256 + 16);
    for (k, e) in &store.envelopes {
        let caps = e.capsule_ids.iter().fold(JsonArr::new(), |a, c| a.str(c));
        let pits = e.pitfall_ids.iter().fold(JsonArr::new(), |a, p| a.str(p));
        let s = JsonObj::with_capacity(256)
            .str("envelope_id", &e.envelope_id).str("session_id", &e.session_id)
            .str("client", &e.client).str("source_digest", &e.source_digest)
            .arr("capsule_ids", caps).arr("pitfall_ids", pits)
            .usize("estimated_tokens", e.estimated_tokens).str("stage", &e.stage)
            .u64("timestamp_utc", e.timestamp_utc).bool("included_in_input", e.included_in_input)
            .bool("included_before_first_patch", e.included_before_first_patch)
            .raw("included_at_utc", &opt_u64_raw(e.included_at_utc))
            .bool("patch_bound", e.patch_bound).str("patch_digest", &e.patch_digest)
            .raw("passed", opt_bool_raw(e.passed)).bool("first_patch", e.first_patch)
            .raw("patch_bound_at_utc", &opt_u64_raw(e.patch_bound_at_utc)).finish();
        envs_j = envs_j.raw(k, &s);
    }
    let mut eff_j = JsonObj::with_capacity(store.efficacy.len() * 128 + 16);
    for (k, f) in &store.efficacy {
        let s = JsonObj::with_capacity(128)
            .str("id", &f.id).u64("wins", f.wins as u64).u64("losses", f.losses as u64)
            .u64("trials", f.trials as u64).u64("consecutive_losses", f.consecutive_losses as u64)
            .bool("frozen", f.is_auto_frozen()).opt_str("freeze_reason", f.effective_freeze_reason()).finish();
        eff_j = eff_j.raw(k, &s);
    }
    let applied_arr = store.applied_outcomes.iter().fold(JsonArr::new(), |a, k| a.str(k));
    let mut bytes = JsonObj::with_capacity(512)
        .str("schema", DELIVERY_TELEMETRY_SCHEMA).str("schema_version", ENGINE_VERSION)
        .u64("updated_at_utc", store.updated_at_utc)
        .raw("envelopes", &envs_j.finish()).raw("efficacy", &eff_j.finish())
        .arr("applied_outcomes", applied_arr).finish().into_bytes();
    bytes.push(b'\n');
    if (bytes.len() as u64) > MAX_TELEMETRY_FILE_BYTES {
        return Err(format!(
            "TELEMETRY_SIZE_CAP_EXCEEDED: {} bytes > {} bytes",
            bytes.len(),
            MAX_TELEMETRY_FILE_BYTES
        ));
    }
    atomic_write_file_secure(store_path, &bytes)
}

fn collect_frozen_ids(store: &TelemetryStore) -> BTreeSet<String> {
    store.efficacy.iter().filter(|(_, r)| r.is_auto_frozen()).map(|(id, _)| id.clone()).collect()
}

fn validate_existing_envelope<'a>(store: &'a TelemetryStore, env_id: &str, client: &str, sess_in: &str, src_dig: &str) -> Result<&'a EnvelopeTelemetryRecord, String> {
    let env = store.envelopes.get(env_id).ok_or_else(|| format!("UNKNOWN_ENVELOPE_ID: '{env_id}'"))?;
    if env.client != client { return Err(format!("CLIENT_MISMATCH: expected '{}', got '{client}'", env.client)); }
    if !sess_in.is_empty() && env.session_id != sess_in { return Err(format!("SESSION_MISMATCH: expected '{}', got '{sess_in}'", env.session_id)); }
    if !src_dig.is_empty() && !env.source_digest.is_empty() && env.source_digest != src_dig { return Err("SOURCE_DIGEST_MISMATCH".to_string()); }
    Ok(env)
}

/// Record a receipt transition (`issued`, `included_in_input`, or `patch_bound`) atomically under `<store>.lock`.
#[allow(clippy::too_many_arguments)]
pub fn record_telemetry_event(
    store_path: &Path, client: &str, stage: &str, session_id: &str, envelope_id: &str,
    source_digest: &str, patch_digest: &str, capsule_ids: &[String], pitfall_ids: &[String],
    estimated_tokens: usize, passed: Option<bool>,
) -> Result<String, String> {
    if !is_supported_client(client) { return Err(format!("UNSUPPORTED_CLIENT: '{client}'")); }
    if !SUPPORTED_STAGES.contains(&stage) { return Err(format!("UNSUPPORTED_STAGE: '{stage}'")); }
    let env_id = validate_id_token("envelope_id", envelope_id, true)?;
    let sess_in = validate_id_token("session_id", session_id, stage == "issued")?;
    let src_dig = validate_id_token("source_digest", source_digest, false)?;
    let (clean_caps, clean_pits) = if stage == "issued" { (dedupe_ids(capsule_ids)?, dedupe_ids(pitfall_ids)?) } else { (Vec::new(), Vec::new()) };
    let (p_dig_pre, pass_pre) = if stage == "patch_bound" {
        (validate_id_token("patch_digest", patch_digest, true)?, Some(passed.ok_or_else(|| "MISSING_PASSED_FLAG".to_string())?))
    } else { (String::new(), None) };
    let now = now_unix_secs();
    let _lock = StoreLockGuard::acquire(store_path)?;
    let mut store = load_store(store_path)?;
    let mut newly_frozen = Vec::new();
    let mut efficacy_updated = false;
    let (res_sess, res_incl_before, res_first_patch, res_passed): (String, bool, bool, Option<bool>);
    match stage {
        "issued" => {
            if store.envelopes.contains_key(&env_id) { return Err(format!("DUPLICATE_ENVELOPE_ID: '{env_id}'")); }
            store.envelopes.insert(env_id.clone(), EnvelopeTelemetryRecord {
                envelope_id: env_id.clone(), session_id: sess_in.clone(), client: client.to_string(),
                source_digest: src_dig, capsule_ids: clean_caps, pitfall_ids: clean_pits,
                estimated_tokens, stage: "issued".to_string(), timestamp_utc: now,
                included_in_input: false, included_before_first_patch: false, included_at_utc: None,
                patch_bound: false, patch_digest: String::new(), passed: None, first_patch: false, patch_bound_at_utc: None,
            });
            (res_sess, res_incl_before, res_first_patch, res_passed) = (sess_in, false, false, None);
        }
        "included_in_input" => {
            let target_sess = validate_existing_envelope(&store, &env_id, client, &sess_in, &src_dig)?.session_id.clone();
            let has_patch = store.envelopes.values().any(|e| e.client == client && e.session_id == target_sess && e.patch_bound);
            let env = store.envelopes.get_mut(&env_id).ok_or_else(|| format!("UNKNOWN_ENVELOPE_ID: '{env_id}'"))?;
            if !env.included_in_input {
                env.included_in_input = true;
                env.included_at_utc = Some(now);
                if env.stage == "issued" { env.stage = "included_in_input".to_string(); }
                if !env.patch_bound && !has_patch { env.included_before_first_patch = true; }
            }
            (res_sess, res_incl_before, res_first_patch, res_passed) = (env.session_id.clone(), env.included_before_first_patch, env.first_patch, env.passed);
        }
        "patch_bound" => {
            let pass_val = pass_pre.ok_or_else(|| "MISSING_PASSED_FLAG".to_string())?;
            let (target_sess, tracked) = {
                let env = validate_existing_envelope(&store, &env_id, client, &sess_in, &src_dig)?;
                if env.patch_bound { return Err(format!("ENVELOPE_ALREADY_PATCH_BOUND: '{env_id}'")); }
                (env.session_id.clone(), env.capsule_ids.iter().chain(env.pitfall_ids.iter()).cloned().collect::<BTreeSet<_>>())
            };
            let is_first = !store.envelopes.values().any(|e| e.client == client && e.session_id == target_sess && e.patch_bound);
            let env = store.envelopes.get_mut(&env_id).ok_or_else(|| format!("UNKNOWN_ENVELOPE_ID: '{env_id}'"))?;
            env.patch_bound = true; env.patch_digest = p_dig_pre.clone(); env.passed = Some(pass_val);
            env.first_patch = is_first; env.patch_bound_at_utc = Some(now); env.stage = "patch_bound".to_string();
            (res_sess, res_incl_before, res_first_patch, res_passed) = (env.session_id.clone(), env.included_before_first_patch, is_first, Some(pass_val));
            if res_incl_before && !tracked.is_empty() {
                for id in tracked {
                    if !store.applied_outcomes.insert(format!("{client}|{res_sess}|{p_dig_pre}|{id}")) {
                        continue;
                    }
                    efficacy_updated = true;
                    let eff = store.efficacy.entry(id.clone()).or_insert_with(|| EfficacyRecord::new(id.clone()));
                    if eff.apply_outcome(pass_val) { newly_frozen.push(id); }
                }
            }
        }
        _ => unreachable!(),
    }
    store.updated_at_utc = now;
    save_store(store_path, &store)?;
    let nf_arr = newly_frozen.iter().fold(JsonArr::new(), |a, id| a.str(id));
    let fr_arr = collect_frozen_ids(&store).into_iter().fold(JsonArr::new(), |a, id| a.str(&id));
    Ok(JsonObj::with_capacity(288)
        .bool("ok", true).str("schema", DELIVERY_TELEMETRY_SCHEMA).str("schema_version", ENGINE_VERSION)
        .str("stage", stage).str("client", client).str("session_id", &res_sess).str("envelope_id", &env_id)
        .bool("included_before_first_patch", res_incl_before).bool("first_patch", res_first_patch)
        .raw("passed", opt_bool_raw(res_passed)).bool("efficacy_updated", efficacy_updated)
        .arr("newly_frozen_ids", nf_arr).arr("frozen_ids", fr_arr).finish())
}

/// Render honest Delivery Gate #3 report JSON across all 4 clients + live efficacy/freeze table.
pub fn render_telemetry_report_json(store_path: &Path) -> Result<String, String> {
    let store = load_store(store_path)?;
    let mut clients = SUPPORTED_CLIENTS.to_vec();
    clients.sort_unstable();
    let (mut total_sessions_all, mut clients_obj) = (0usize, JsonObj::with_capacity(1024));
    for &c in &clients {
        let (mut all_s, mut incl_s) = (BTreeSet::new(), BTreeSet::new());
        let (mut issued_cnt, mut bound_cnt, mut passed_cnt) = (0usize, 0usize, 0usize);
        for env in store.envelopes.values().filter(|e| e.client == c) {
            issued_cnt += 1;
            all_s.insert(env.session_id.as_str());
            if env.included_before_first_patch { incl_s.insert(env.session_id.as_str()); }
            if env.patch_bound { bound_cnt += 1; if env.passed == Some(true) { passed_cnt += 1; } }
        }
        let (tot_s, inc_s) = (all_s.len(), incl_s.len());
        total_sessions_all += tot_s;
        let incl_rate = if tot_s == 0 { 0.0 } else { (inc_s as f64) / (tot_s as f64) };
        let pass_rate = if bound_cnt == 0 { 0.0 } else { (passed_cnt as f64) / (bound_cnt as f64) };
        let c_json = JsonObj::with_capacity(256)
            .str("client", c).usize("total_sessions", tot_s).usize("issued_count", issued_cnt)
            .usize("included_before_first_patch_count", inc_s)
            .raw("included_before_first_patch_rate", &fmt_f64_4(incl_rate))
            .usize("patch_bound_count", bound_cnt).usize("patch_passed_count", passed_cnt)
            .raw("patch_pass_rate", &fmt_f64_4(pass_rate))
            .bool("gate_3_min_10_sessions_met", tot_s >= GATE_3_MIN_SESSIONS).finish();
        clients_obj = clients_obj.raw(c, &c_json);
    }
    let frozen_set = collect_frozen_ids(&store);
    let frozen_arr = frozen_set.iter().fold(JsonArr::new(), |a, id| a.str(id));
    let mut eff_arr = JsonArr::new();
    for eff in store.efficacy.values() {
        eff_arr = eff_arr.obj(
            JsonObj::with_capacity(160)
                .str("id", &eff.id).u64("wins", eff.wins as u64).u64("losses", eff.losses as u64)
                .u64("trials", eff.trials as u64).u64("consecutive_losses", eff.consecutive_losses as u64)
                .f64_2("efficacy_pct", eff.efficacy_pct()).bool("frozen", eff.is_auto_frozen())
                .opt_str("freeze_reason", eff.effective_freeze_reason()),
        );
    }
    Ok(JsonObj::with_capacity(1536)
        .bool("ok", true).str("schema", DELIVERY_TELEMETRY_SCHEMA).str("schema_version", ENGINE_VERSION)
        .usize("total_envelopes", store.envelopes.len()).usize("total_sessions", total_sessions_all)
        .raw("clients", &clients_obj.finish()).arr("frozen_ids", frozen_arr)
        .usize("frozen_count", frozen_set.len()).arr("efficacy_table", eff_arr).finish())
}

/// Strict fail-closed loader for currently auto-frozen capsule/pitfall IDs (propagates I/O or corrupt-store errors).
pub fn try_load_frozen_ids(store_path: &Path) -> Result<BTreeSet<String>, String> {
    load_store(store_path).map(|s| collect_frozen_ids(&s))
}

/// Best-effort loader for currently auto-frozen capsule/pitfall IDs (returns empty set if absent/unreadable).
pub fn load_frozen_ids(store_path: &Path) -> BTreeSet<String> {
    try_load_frozen_ids(store_path).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stages_honest_denominator_two_strike_dead_scar_and_symlink_rejection() {
        let dir = std::env::temp_dir().join(format!("kintsugi_dt_rs_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let store = dir.join("delivery_telemetry.json");
        let (caps, pits) = (vec!["CAP-A".to_string()], vec!["LT-003".to_string()]);
        assert!(record_telemetry_event(&store, "bad_cli", "issued", "s1", "e1", "d1", "", &caps, &pits, 50, None).is_err());
        assert!(record_telemetry_event(&store, "claude_code", "included_in_input", "s1", "missing", "", "", &[], &[], 0, None).is_err());
        record_telemetry_event(&store, "claude_code", "issued", "s1", "e1", "d1", "", &caps, &pits, 90, None).unwrap();
        assert!(record_telemetry_event(&store, "antigravity", "included_in_input", "s1", "e1", "", "", &[], &[], 0, None).is_err());
        record_telemetry_event(&store, "claude_code", "included_in_input", "s1", "e1", "", "", &[], &[], 0, None).unwrap();
        let r1 = record_telemetry_event(&store, "claude_code", "patch_bound", "s1", "e1", "", "p1", &[], &[], 0, Some(false)).unwrap();
        assert!(r1.contains("\"first_patch\":true") && r1.contains("\"efficacy_updated\":true") && r1.contains("\"newly_frozen_ids\":[]"));
        record_telemetry_event(&store, "claude_code", "issued", "s2", "e2", "d2", "", &caps, &[], 60, None).unwrap();
        // Unshown envelope (issued -> patch_bound WITHOUT included_in_input): counts in denominator, MUST NOT update efficacy!
        record_telemetry_event(&store, "claude_code", "issued", "s3", "e3", "d3", "", &caps, &pits, 70, None).unwrap();
        let r3 = record_telemetry_event(&store, "claude_code", "patch_bound", "s3", "e3", "", "p3", &[], &[], 0, Some(false)).unwrap();
        assert!(r3.contains("\"efficacy_updated\":false") && r3.contains("\"newly_frozen_ids\":[]") && load_frozen_ids(&store).is_empty());
        let rep3 = render_telemetry_report_json(&store).unwrap();
        assert!(parse_json_value(&rep3).is_ok() && rep3.contains("\"total_sessions\":3") && rep3.contains("\"patch_bound_count\":2") && rep3.contains("\"included_before_first_patch_rate\":0.3333"));
        // Shown envelope (issued -> included_in_input -> patch_bound(false)): triggers 2-strike freeze!
        record_telemetry_event(&store, "claude_code", "issued", "s4", "e4", "d4", "", &caps, &pits, 70, None).unwrap();
        record_telemetry_event(&store, "claude_code", "included_in_input", "s4", "e4", "", "", &[], &[], 0, None).unwrap();
        let r4 = record_telemetry_event(&store, "claude_code", "patch_bound", "s4", "e4", "", "p4", &[], &[], 0, Some(false)).unwrap();
        assert!(r4.contains("\"efficacy_updated\":true") && r4.contains("\"CAP-A\"") && r4.contains("\"LT-003\"") && load_frozen_ids(&store).contains("CAP-A"));
        // Sticky-freeze invariant: pre-seeded 4/30 dead scar and consecutive_losses=2 MUST stay frozen on passed=true!
        let mut dead = EfficacyRecord { id: "CAP-DEAD".into(), wins: 4, losses: 26, trials: 30, consecutive_losses: 0, frozen: false, freeze_reason: None };
        assert!(dead.is_auto_frozen() && dead.effective_freeze_reason() == Some("dead_scar_low_efficacy"));
        assert!(!dead.apply_outcome(true));
        assert!(dead.frozen && dead.is_auto_frozen() && dead.effective_freeze_reason() == Some("dead_scar_low_efficacy"));
        let mut two_s = EfficacyRecord { id: "CAP-2S".into(), wins: 0, losses: 2, trials: 2, consecutive_losses: 2, frozen: false, freeze_reason: None };
        assert!(!two_s.apply_outcome(true));
        assert!(two_s.frozen && two_s.is_auto_frozen() && two_s.effective_freeze_reason() == Some("two_strike_consecutive_losses"));
        // Corrupt store types & 2^32 u32 overflow must fail closed!
        for bad in [
            r#"{"schema":123,"envelopes":[],"efficacy":"corrupt"}"#,
            r#"{"schema":"DeliveryTelemetry/1","envelopes":[],"efficacy":{}}"#,
            r#"{"schema":"DeliveryTelemetry/1","envelopes":{},"efficacy":"corrupt"}"#,
            r#"{"schema":"DeliveryTelemetry/1","updated_at_utc":true,"envelopes":{},"efficacy":{}}"#,
            r#"{"schema":"DeliveryTelemetry/1","envelopes":{},"efficacy":{"CAP-OVF":{"id":"CAP-OVF","wins":0,"losses":0,"trials":4294967296,"consecutive_losses":0,"frozen":false}}}"#,
            r#"{"schema":"DeliveryTelemetry/1","envelopes":{},"efficacy":{"CAP-OVF2":{"id":"CAP-OVF2","wins":0,"losses":0,"trials":2,"consecutive_losses":4294967296,"frozen":false}}}"#,
        ] {
            let bad_p = dir.join("bad_store.json");
            fs::write(&bad_p, bad).unwrap();
            assert!(render_telemetry_report_json(&bad_p).is_err(), "expected error for {bad}");
        }
        let null_ts = dir.join("null_ts.json");
        fs::write(&null_ts, r#"{"schema":"DeliveryTelemetry/1","updated_at_utc":null,"envelopes":{},"efficacy":{}}"#).unwrap();
        assert!(render_telemetry_report_json(&null_ts).is_ok());
        #[cfg(unix)]
        {
            let link = dir.join("sym_store.json");
            std::os::unix::fs::symlink(&store, &link).unwrap();
            assert!(render_telemetry_report_json(&link).is_err());
            assert!(record_telemetry_event(&link, "claude_code", "issued", "s9", "e9", "d9", "", &[], &[], 0, None).is_err());
            let (outside, safe_dir) = (dir.join("outside"), dir.join("safe_dir"));
            fs::create_dir_all(&outside).unwrap();
            fs::create_dir_all(&safe_dir).unwrap();
            std::os::unix::fs::symlink(&outside, safe_dir.join("sym_sub")).unwrap();
            let nested = safe_dir.join("sym_sub").join("nested").join("delivery_telemetry.json");
            assert!(record_telemetry_event(&nested, "claude_code", "issued", "s10", "e10", "d10", "", &[], &[], 0, None).is_err());
            assert!(render_telemetry_report_json(&nested).is_err());
            assert!(!outside.join("nested").exists());
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unrecognized_json_preserved_multifile_patch_dedup_and_late_stage_parity() {
        let dir = std::env::temp_dir().join(format!("kintsugi_dt_v301_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // HIGH #5: unrecognized existing JSON file MUST fail closed without overwriting bytes!
        let foreign = dir.join("foreign.json");
        fs::write(&foreign, br#"{"note":1}"#).unwrap();
        let err = record_telemetry_event(&foreign, "claude_code", "issued", "s1", "e1", "d1", "", &[], &[], 10, None).unwrap_err();
        assert!(err.contains("UNRECOGNIZED_TELEMETRY_STORE"), "got {err}");
        assert_eq!(fs::read(&foreign).unwrap(), br#"{"note":1}"#);
        let missing_sections = dir.join("missing_sec.json");
        fs::write(&missing_sections, br#"{"schema":"DeliveryTelemetry/1"}"#).unwrap();
        assert!(record_telemetry_event(&missing_sections, "claude_code", "issued", "s1", "e1", "d1", "", &[], &[], 10, None).is_err());
        assert_eq!(fs::read(&missing_sections).unwrap(), br#"{"schema":"DeliveryTelemetry/1"}"#);
        // 0-byte empty file auto-initializes cleanly
        let zero = dir.join("empty.json");
        fs::write(&zero, b"").unwrap();
        assert!(record_telemetry_event(&zero, "claude_code", "issued", "s0", "e0", "d0", "", &[], &[], 5, None).is_ok());

        // HIGH #6: 2 envelopes in same session bound to same patch_digest="p" count ONCE; 2nd patch "p2" freezes!
        let dedup_store = dir.join("dedup.json");
        let caps = vec!["CAP-DEDUP".to_string()];
        record_telemetry_event(&dedup_store, "claude_code", "issued", "s1", "e1", "d1", "", &caps, &[], 50, None).unwrap();
        record_telemetry_event(&dedup_store, "claude_code", "included_in_input", "s1", "e1", "", "", &[], &[], 0, None).unwrap();
        record_telemetry_event(&dedup_store, "claude_code", "issued", "s1", "e2", "d2", "", &caps, &[], 50, None).unwrap();
        record_telemetry_event(&dedup_store, "claude_code", "included_in_input", "s1", "e2", "", "", &[], &[], 0, None).unwrap();
        let r1 = record_telemetry_event(&dedup_store, "claude_code", "patch_bound", "s1", "e1", "", "p", &[], &[], 0, Some(false)).unwrap();
        let r2 = record_telemetry_event(&dedup_store, "claude_code", "patch_bound", "s1", "e2", "", "p", &[], &[], 0, Some(false)).unwrap();
        assert!(r1.contains("\"efficacy_updated\":true") && r2.contains("\"efficacy_updated\":false"));
        let st1 = load_store(&dedup_store).unwrap();
        assert_eq!(st1.envelopes.len(), 2);
        let eff1 = st1.efficacy.get("CAP-DEDUP").unwrap();
        assert_eq!((eff1.losses, eff1.trials, eff1.is_auto_frozen()), (1, 1, false));
        // Late included_in_input (MEDIUM #9) after session already has a patch: updates stage to "included_in_input" while included_before_first_patch stays false!
        record_telemetry_event(&dedup_store, "claude_code", "issued", "s1", "e_late", "d3", "", &caps, &[], 20, None).unwrap();
        let rl = record_telemetry_event(&dedup_store, "claude_code", "included_in_input", "s1", "e_late", "", "", &[], &[], 0, None).unwrap();
        assert!(rl.contains("\"included_before_first_patch\":false"));
        let st_late = load_store(&dedup_store).unwrap();
        let rec_late = st_late.envelopes.get("e_late").unwrap();
        assert_eq!(rec_late.stage, "included_in_input");
        assert!(rec_late.included_in_input && !rec_late.included_before_first_patch);
        // 2nd distinct failing patch "p2" triggers 2-strike freeze!
        record_telemetry_event(&dedup_store, "claude_code", "issued", "s2", "e3", "d4", "", &caps, &[], 50, None).unwrap();
        record_telemetry_event(&dedup_store, "claude_code", "included_in_input", "s2", "e3", "", "", &[], &[], 0, None).unwrap();
        let r3 = record_telemetry_event(&dedup_store, "claude_code", "patch_bound", "s2", "e3", "", "p2", &[], &[], 0, Some(false)).unwrap();
        assert!(r3.contains("\"newly_frozen_ids\":[\"CAP-DEDUP\"]"));
        let st2 = load_store(&dedup_store).unwrap();
        let eff2 = st2.efficacy.get("CAP-DEDUP").unwrap();
        assert_eq!((eff2.losses, eff2.trials, eff2.is_auto_frozen()), (2, 2, true));
        // Pipe '|' rejected in session_id, patch_digest, and item_id; malformed envelope fields fail closed; legacy v3.0.0 backfill prevents double-count; u32::MAX saturates!
        assert!(record_telemetry_event(&dedup_store, "claude_code", "issued", "s|1", "ep1", "d", "", &[], &[], 0, None).is_err());
        assert!(record_telemetry_event(&dedup_store, "claude_code", "issued", "sp", "ep2", "d", "", &["CAP|1".to_string()], &[], 0, None).is_err());
        record_telemetry_event(&dedup_store, "claude_code", "issued", "sp", "ep3", "d", "", &[], &[], 0, None).unwrap();
        assert!(record_telemetry_event(&dedup_store, "claude_code", "patch_bound", "sp", "ep3", "", "p|1", &[], &[], 0, Some(true)).is_err());
        for bad_env in [
            r#"{"schema":"DeliveryTelemetry/1","envelopes":{"e1":{"envelope_id":"e1","session_id":"s1","client":"claude_code","stage":"issued","patch_bound":"false"}},"efficacy":{}}"#,
            r#"{"schema":"DeliveryTelemetry/1","envelopes":{"e1":{"envelope_id":"e1","session_id":"s1","client":"claude_code","stage":"issued","capsule_ids":"CAP-1"}},"efficacy":{}}"#,
            r#"{"schema":"DeliveryTelemetry/1","envelopes":{"e1":{"envelope_id":"e1","session_id":"s1","client":"claude_code","stage":"issued","estimated_tokens":null}},"efficacy":{}}"#,
        ] {
            let bp = dir.join("bad_env_r2.json");
            fs::write(&bp, bad_env).unwrap();
            assert!(load_store(&bp).is_err(), "expected err for {bad_env}");
        }
        let leg = dir.join("legacy_backfill.json");
        fs::write(&leg, r#"{"schema":"DeliveryTelemetry/1","envelopes":{"e1":{"envelope_id":"e1","session_id":"s1","client":"claude_code","stage":"patch_bound","capsule_ids":["CAP-L"],"pitfall_ids":[],"included_in_input":true,"included_before_first_patch":true,"patch_bound":true,"patch_digest":"p1","passed":false},"e2":{"envelope_id":"e2","session_id":"s1","client":"claude_code","stage":"included_in_input","capsule_ids":["CAP-L"],"pitfall_ids":[],"included_in_input":true,"included_before_first_patch":true,"patch_bound":false,"patch_digest":"","passed":null}},"efficacy":{"CAP-L":{"id":"CAP-L","wins":0,"losses":1,"trials":1,"consecutive_losses":1,"frozen":false,"freeze_reason":null}}}"#).unwrap();
        let rl_bf = record_telemetry_event(&leg, "claude_code", "patch_bound", "s1", "e2", "", "p1", &[], &[], 0, Some(false)).unwrap();
        assert!(rl_bf.contains("\"efficacy_updated\":false") && load_frozen_ids(&leg).is_empty());
        let mut sat = EfficacyRecord { id: "CAP-SAT".into(), wins: u32::MAX, losses: u32::MAX, trials: u32::MAX, consecutive_losses: u32::MAX, frozen: false, freeze_reason: None };
        sat.apply_outcome(false);
        assert_eq!((sat.trials, sat.losses, sat.consecutive_losses), (u32::MAX, u32::MAX, u32::MAX));
        let _ = fs::remove_dir_all(&dir);
    }
}
