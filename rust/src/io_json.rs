//! Zero-dependency JSON escaping, typed object/array builders (`RawJson`), FNV-1a hashing,
//! OS-hardened `O_NOFOLLOW`/reparse-point handle verification, and `BrokenPipe`-safe atomic CLI I/O.
//!
//! ## Component-by-Component Symlink & Reparse-Point Defense Architecture
//! 1. **Ancestor Directory Confinement (`scanner::collect_files_confined`, `audit::memories`):**
//!    Directory walks inspect every path component via `symlink_metadata`, rejecting `ParentDir` (`..`),
//!    directory symlinks (`file_type().is_symlink()`), and Windows reparse points
//!    (`FILE_ATTRIBUTE_REPARSE_POINT`) before descending, paired with `canonicalize` prefix confinement.
//! 2. **Leaf Handle Open & Identity Verification ([`read_regular_bytes_fd_verified`]):**
//!    - **Unix:** `symlink_metadata` pre-check -> `open(O_RDONLY | O_NOFOLLOW)` on the terminal path
//!      component -> `fstat` (`File::metadata`) verifying `is_file()` AND exact `(dev, ino)` match
//!      against the pre-open `symlink_metadata`, eliminating stat-to-open symlink/file swap TOCTOU
//!      races without requiring external `openat` libc bindings -> bounded `take(max_bytes + 1)` read.
//!    - **Windows:** `CreateFileW` with `FILE_FLAG_OPEN_REPARSE_POINT` (preventing kernel reparse/junction
//!      traversal on open) -> `GetFileType == FILE_TYPE_DISK` -> `GetFileInformationByHandle` rejecting
//!      `FILE_ATTRIBUTE_REPARSE_POINT` and `FILE_ATTRIBUTE_DIRECTORY` -> bounded `take(max_bytes + 1)` read.
//! 3. **FIFO / device swap hang defense (Unix):** the leaf `open()` also passes `O_NONBLOCK`, so if an
//!    attacker swaps a regular file for a FIFO between `symlink_metadata` and `open`, the call returns
//!    immediately instead of blocking forever waiting for a writer. The `fstat` step then rejects it.
//!    For regular files, `O_NONBLOCK` has no effect on `read`.
//!
//! ## Deliberate Non-Goals
//! - **Hardlinks (`nlink > 1`) are accepted on purpose.** The Nix store, pnpm/Cargo hardlink caches and
//!   `git worktree` checkouts use hardlinks legitimately for source files. A hardlink cannot cross
//!   filesystems and cannot point at a directory. `(dev, ino)` identity already guarantees that the
//!   bytes we read belong to the inode we validated.
//! - **Ancestor-directory TOCTOU:** `O_NOFOLLOW` only protects the *terminal* path component. A
//!   concurrent swap of an *ancestor* directory with a symlink after the confined walk is outside the
//!   leaf-open guarantee. That would need `openat`-relative traversal, which is not reachable from pure
//!   `std`. It is mitigated by walk-time component checks plus `canonicalize` prefix confinement (item 1).

use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

/// Canonical engine version sourced from `Cargo.toml` at compile time.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
/// Standard 64-bit FNV-1a offset basis.
pub const FNV1A_64_INIT: u64 = 0xcbf29ce484222325;
/// Maximum stdin read size to prevent stdin-bomb OOM DoS.
pub const MAX_STDIN_BYTES: u64 = 16 * 1024 * 1024;

const FNV1A_64_PRIME: u64 = 0x100000001b3;
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// Validated pre-serialized JSON fragment wrapper for [`JsonObj::raw_json`] and [`JsonArr::raw_json`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawJson(pub String);

/// Explicit non-panicking, non-exiting outcome of writing to `stdout` (or any `Write` sink).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteOutcome {
    Written,
    BrokenPipe,
    IoError(String),
}

/// Compute 64-bit FNV-1a hash over `data` starting from `seed`.
#[inline]
pub fn fnv1a_64(data: &[u8], seed: u64) -> u64 {
    let mut hash = seed;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV1A_64_PRIME);
    }
    hash
}

/// Compute 16-char lowercase hexadecimal FNV-1a digest of `data` using `FNV1A_64_INIT`.
#[inline]
pub fn fnv1a_64_hex(data: &[u8]) -> String {
    format!("{:016x}", fnv1a_64(data, FNV1A_64_INIT))
}

/// Escape `input` according to RFC 8259 Section 7 directly into `out` without extra allocations.
#[inline]
pub fn json_escape_into(input: &str, out: &mut String) {
    if input.bytes().all(|b| b >= 0x20 && b != b'"' && b != b'\\') {
        out.push_str(input);
        return;
    }
    out.reserve(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let v = c as u8;
                out.push_str("\\u00");
                out.push(HEX_LOWER[(v >> 4) as usize] as char);
                out.push(HEX_LOWER[(v & 0x0f) as usize] as char);
            }
            c => out.push(c),
        }
    }
}

/// Return a freshly allocated RFC 8259 escaped JSON string body (without surrounding quotes).
#[inline]
pub fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    json_escape_into(input, &mut out);
    out
}

/// Zero-dependency deterministic JSON array builder.
#[derive(Debug, Clone)]
pub struct JsonArr {
    buf: String,
    has_items: bool,
}

impl Default for JsonArr {
    fn default() -> Self { Self::new() }
}

impl JsonArr {
    #[inline]
    pub fn new() -> Self { Self::with_capacity(64) }

    #[inline]
    pub fn with_capacity(cap: usize) -> Self {
        let mut buf = String::with_capacity(cap.max(2));
        buf.push('[');
        Self { buf, has_items: false }
    }

    #[inline]
    fn push_sep(&mut self) {
        if self.has_items { self.buf.push(','); } else { self.has_items = true; }
    }

    #[inline]
    pub fn str(mut self, v: &str) -> Self {
        self.push_sep();
        self.buf.push('"');
        json_escape_into(v, &mut self.buf);
        self.buf.push('"');
        self
    }

    #[inline]
    pub fn raw(mut self, raw_json: &str) -> Self {
        debug_assert!(!raw_json.trim().is_empty(), "JsonArr::raw value must not be empty");
        self.push_sep();
        self.buf.push_str(raw_json);
        self
    }

    #[inline]
    pub fn raw_json(self, val: RawJson) -> Self { self.raw(&val.0) }

    #[inline]
    pub fn u64(mut self, v: u64) -> Self {
        self.push_sep();
        let _ = write!(self.buf, "{v}");
        self
    }

    #[inline]
    pub fn obj(mut self, obj: JsonObj) -> Self {
        self.push_sep();
        self.buf.push_str(&obj.buf);
        self.buf.push('}');
        self
    }

    #[inline]
    pub fn finish(mut self) -> String {
        self.buf.push(']');
        self.buf
    }
}

/// Zero-dependency deterministic JSON object builder.
#[derive(Debug, Clone)]
pub struct JsonObj {
    buf: String,
    has_fields: bool,
}

impl Default for JsonObj {
    fn default() -> Self { Self::new() }
}

impl JsonObj {
    #[inline]
    pub fn new() -> Self { Self::with_capacity(128) }

    #[inline]
    pub fn with_capacity(cap: usize) -> Self {
        let mut buf = String::with_capacity(cap.max(2));
        buf.push('{');
        Self { buf, has_fields: false }
    }

    #[inline]
    fn push_key(&mut self, k: &str) {
        if self.has_fields { self.buf.push(','); } else { self.has_fields = true; }
        self.buf.push('"');
        json_escape_into(k, &mut self.buf);
        self.buf.push_str("\":");
    }

    #[inline]
    pub fn str(mut self, k: &str, v: &str) -> Self {
        self.push_key(k);
        self.buf.push('"');
        json_escape_into(v, &mut self.buf);
        self.buf.push('"');
        self
    }

    #[inline]
    pub fn opt_str(mut self, k: &str, v: Option<&str>) -> Self {
        self.push_key(k);
        match v {
            Some(s) => { self.buf.push('"'); json_escape_into(s, &mut self.buf); self.buf.push('"'); }
            None => self.buf.push_str("null"),
        }
        self
    }

    #[inline]
    pub fn arr(mut self, k: &str, arr: JsonArr) -> Self {
        self.push_key(k);
        self.buf.push_str(&arr.buf);
        self.buf.push(']');
        self
    }

    #[inline]
    pub fn raw(mut self, k: &str, raw_json: &str) -> Self {
        debug_assert!(!raw_json.trim().is_empty(), "JsonObj::raw value for key '{k}' must not be empty");
        self.push_key(k);
        self.buf.push_str(raw_json);
        self
    }

    #[inline]
    pub fn raw_json(self, k: &str, val: RawJson) -> Self { self.raw(k, &val.0) }

    #[inline]
    pub fn bool(mut self, k: &str, v: bool) -> Self {
        self.push_key(k);
        self.buf.push_str(if v { "true" } else { "false" });
        self
    }

    #[inline]
    pub fn u64(mut self, k: &str, v: u64) -> Self { self.push_key(k); let _ = write!(self.buf, "{v}"); self }

    #[inline]
    pub fn usize(mut self, k: &str, v: usize) -> Self { self.push_key(k); let _ = write!(self.buf, "{v}"); self }

    #[inline]
    pub fn i64(mut self, k: &str, v: i64) -> Self { self.push_key(k); let _ = write!(self.buf, "{v}"); self }

    #[inline]
    pub fn f64_2(mut self, k: &str, v: f64) -> Self {
        self.push_key(k);
        let _ = write!(self.buf, "{:.2}", if v.is_finite() { v } else { 0.0 });
        self
    }

    #[inline]
    pub fn f64_3(mut self, k: &str, v: f64) -> Self {
        self.push_key(k);
        let _ = write!(self.buf, "{:.3}", if v.is_finite() { v } else { 0.0 });
        self
    }

    #[inline]
    pub fn finish(mut self) -> String { self.buf.push('}'); self.buf }
}

#[inline]
fn try_write_to_sink<W: Write>(mut sink: W, bytes: &[u8]) -> io::Result<()> {
    sink.write_all(bytes)?;
    sink.flush()
}

#[inline]
fn write_sink_outcome<W: Write>(sink: W, bytes: &[u8]) -> WriteOutcome {
    match try_write_to_sink(sink, bytes) {
        Ok(()) => WriteOutcome::Written,
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => WriteOutcome::BrokenPipe,
        Err(err) => WriteOutcome::IoError(err.to_string()),
    }
}

/// Atomically write `bytes` to locked `stdout` and flush, returning raw [`io::Result`] without exiting.
pub fn try_write_stdout_bytes(bytes: &[u8]) -> io::Result<()> {
    try_write_to_sink(io::stdout().lock(), bytes)
}

/// Atomically write `bytes` to locked `stdout` and classify the result into [`WriteOutcome`] without exiting.
pub fn write_stdout_outcome(bytes: &[u8]) -> WriteOutcome {
    write_sink_outcome(io::stdout().lock(), bytes)
}

/// Write `msg` (appending `\n` when absent) to locked `stderr`, silently ignoring `BrokenPipe`
/// and stderr I/O errors so diagnostic reporting never panics (unlike `eprintln!`).
pub fn write_stderr_safe(msg: &str) {
    let mut err_lock = io::stderr().lock();
    if msg.ends_with('\n') {
        let _ = err_lock.write_all(msg.as_bytes());
    } else {
        let mut buf = Vec::with_capacity(msg.len().saturating_add(1));
        buf.extend_from_slice(msg.as_bytes());
        buf.push(b'\n');
        let _ = err_lock.write_all(&buf);
    }
    let _ = err_lock.flush();
}

#[cold]
fn exit_on_unwritten_stdout(outcome: WriteOutcome) -> ! {
    match outcome {
        WriteOutcome::BrokenPipe => std::process::exit(0),
        WriteOutcome::IoError(err_msg) => {
            let diag = JsonObj::new()
                .bool("ok", false)
                .str("error", &format!("STDOUT_IO_ERROR: {err_msg}"))
                .finish();
            write_stderr_safe(&diag);
            std::process::exit(2);
        }
        WriteOutcome::Written => unreachable!(),
    }
}

/// Write `bytes` to locked `stdout` via [`write_stdout_outcome`], exiting `0` cleanly on `BrokenPipe`.
pub fn write_stdout_bytes(bytes: &[u8]) {
    let outcome = write_stdout_outcome(bytes);
    if outcome != WriteOutcome::Written {
        exit_on_unwritten_stdout(outcome);
    }
}

/// Write UTF-8 string `s` to locked `stdout` via [`write_stdout_outcome`].
#[inline]
pub fn write_stdout_str(s: &str) {
    let outcome = write_stdout_outcome(s.as_bytes());
    if outcome != WriteOutcome::Written {
        exit_on_unwritten_stdout(outcome);
    }
}

/// Write UTF-8 string `s` followed by `\n` in one contiguous buffer via [`write_stdout_outcome`].
pub fn write_stdout_ln(s: &str) {
    let mut buf = Vec::with_capacity(s.len().saturating_add(1));
    buf.extend_from_slice(s.as_bytes());
    buf.push(b'\n');
    let outcome = write_stdout_outcome(&buf);
    if outcome != WriteOutcome::Written {
        exit_on_unwritten_stdout(outcome);
    }
}

/// Read all UTF-8 text from `stdin`, enforcing `MAX_STDIN_BYTES` limit.
///
/// Raw bytes are read first and the size limit is checked *before* UTF-8 decoding. Oversized input
/// truncated in the middle of a multi-byte sequence therefore always reports the size error, never a
/// misleading UTF-8 error.
pub fn read_stdin_checked() -> Result<String, String> {
    let mut raw = Vec::new();
    io::stdin()
        .lock()
        .take(MAX_STDIN_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|e| format!("STDIN_IO_ERROR: {e}"))?;
    if (raw.len() as u64) > MAX_STDIN_BYTES {
        return Err(format!("STDIN_IO_ERROR: input exceeds MAX_STDIN_BYTES ({MAX_STDIN_BYTES})"));
    }
    String::from_utf8(raw).map_err(|e| format!("STDIN_IO_ERROR: stdin is not valid UTF-8: {e}"))
}

/// Open `path` read-only with `O_NOFOLLOW | O_NONBLOCK` on the terminal component.
///
/// - `O_NOFOLLOW`: a symlink at the leaf makes the open fail (`ELOOP`) instead of being followed.
/// - `O_NONBLOCK`: a FIFO swapped in after the pre-open `symlink_metadata` cannot hang `open()`.
///   The caller's `fstat` + [`verify_unix_regular_identity`] then rejects it. Reads on regular files
///   are unaffected by `O_NONBLOCK`.
///
/// Flag values are hard-coded per OS/arch, mirroring the system `<fcntl.h>` headers, because the
/// crate has no external dependencies (no `libc`).
/// QNX Neutrino (`nto`): `O_NOFOLLOW = 0o010000` and `O_NONBLOCK = 0o000200`, per QNX `<fcntl.h>`
/// and the `libc` crate's `nto` module.
#[cfg(unix)]
fn open_regular_nofollow(path: &Path) -> io::Result<File> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    #[cfg(any(
        target_os = "macos", target_os = "ios", target_os = "tvos", target_os = "watchos",
        target_os = "visionos", target_os = "freebsd", target_os = "dragonfly",
        target_os = "netbsd", target_os = "openbsd"
    ))]
    const O_NOFOLLOW_FLAG: i32 = 0x0100;
    #[cfg(any(target_os = "solaris", target_os = "illumos"))]
    const O_NOFOLLOW_FLAG: i32 = 0x20000;
    #[cfg(target_os = "haiku")]
    const O_NOFOLLOW_FLAG: i32 = 0x0008_0000;
    #[cfg(target_os = "aix")]
    const O_NOFOLLOW_FLAG: i32 = 0x0100_0000;
    #[cfg(target_os = "nto")]
    const O_NOFOLLOW_FLAG: i32 = 0o010000;
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(target_arch = "aarch64", target_arch = "arm", target_arch = "m68k", target_arch = "powerpc", target_arch = "powerpc64")
    ))]
    const O_NOFOLLOW_FLAG: i32 = 0o100000;
    #[cfg(all(
        target_os = "linux",
        any(
            target_arch = "x86", target_arch = "x86_64", target_arch = "riscv32", target_arch = "riscv64",
            target_arch = "s390x", target_arch = "mips", target_arch = "mips64", target_arch = "sparc",
            target_arch = "sparc64", target_arch = "loongarch64", target_arch = "hexagon", target_arch = "csky"
        )
    ))]
    const O_NOFOLLOW_FLAG: i32 = 0o400000;
    #[cfg(all(target_os = "android", any(target_arch = "x86", target_arch = "x86_64")))]
    const O_NOFOLLOW_FLAG: i32 = 0o400000;
    #[cfg(not(any(
        target_os = "macos", target_os = "ios", target_os = "tvos", target_os = "watchos",
        target_os = "visionos", target_os = "freebsd", target_os = "dragonfly",
        target_os = "netbsd", target_os = "openbsd", target_os = "solaris", target_os = "illumos",
        target_os = "haiku", target_os = "aix", target_os = "nto",
        all(any(target_os = "linux", target_os = "android"), any(target_arch = "aarch64", target_arch = "arm", target_arch = "m68k", target_arch = "powerpc", target_arch = "powerpc64")),
        all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64", target_arch = "riscv32", target_arch = "riscv64", target_arch = "s390x", target_arch = "mips", target_arch = "mips64", target_arch = "sparc", target_arch = "sparc64", target_arch = "loongarch64", target_arch = "hexagon", target_arch = "csky")),
        all(target_os = "android", any(target_arch = "x86", target_arch = "x86_64"))
    )))]
    compile_error!("Unsupported Unix target for O_NOFOLLOW");

    #[cfg(any(
        target_os = "macos", target_os = "ios", target_os = "tvos", target_os = "watchos",
        target_os = "visionos", target_os = "freebsd", target_os = "dragonfly",
        target_os = "netbsd", target_os = "openbsd"
    ))]
    const O_NONBLOCK_FLAG: i32 = 0x0004;
    #[cfg(any(target_os = "solaris", target_os = "illumos"))]
    const O_NONBLOCK_FLAG: i32 = 0x80;
    #[cfg(target_os = "haiku")]
    const O_NONBLOCK_FLAG: i32 = 0x0080;
    #[cfg(target_os = "aix")]
    const O_NONBLOCK_FLAG: i32 = 0x04;
    #[cfg(target_os = "nto")]
    const O_NONBLOCK_FLAG: i32 = 0o000200;
    #[cfg(all(target_os = "linux", any(target_arch = "mips", target_arch = "mips64")))]
    const O_NONBLOCK_FLAG: i32 = 0x80;
    #[cfg(all(target_os = "linux", any(target_arch = "sparc", target_arch = "sparc64")))]
    const O_NONBLOCK_FLAG: i32 = 0x4000;
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        not(any(target_arch = "mips", target_arch = "mips64", target_arch = "sparc", target_arch = "sparc64"))
    ))]
    const O_NONBLOCK_FLAG: i32 = 0o4000;

    OpenOptions::new().read(true).custom_flags(O_NOFOLLOW_FLAG | O_NONBLOCK_FLAG).open(path)
}

/// Verify that the handle-derived metadata `fd_meta` (from `File::metadata`, i.e. `fstat`) is a regular
/// file whose `(dev, ino)` exactly matches the pre-open `symlink_metadata` snapshot `pre_meta`.
///
/// A mismatch means the path was swapped between the stat and the open (TOCTOU), so the call fails
/// with `InvalidData`. A non-regular target (FIFO, device, directory, socket) fails with `InvalidInput`.
/// `nlink > 1` is deliberately *not* rejected (see the module docs: Nix store, pnpm/Cargo caches,
/// `git worktree`).
#[cfg(unix)]
pub(crate) fn verify_unix_regular_identity(
    pre_meta: &std::fs::Metadata,
    fd_meta: &std::fs::Metadata,
) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    if !pre_meta.file_type().is_file() || !fd_meta.file_type().is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "NOT_REGULAR_FILE: target is not a regular file"));
    }
    if pre_meta.dev() != fd_meta.dev() || pre_meta.ino() != fd_meta.ino() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "IDENTITY_MISMATCH: (dev, ino) changed between symlink_metadata and open",
        ));
    }
    Ok(())
}

#[cfg(windows)]
mod win_nofollow {
    use std::fs::File;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
    use std::path::Path;
    use std::ptr;

    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_SHARE_ALL: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_TYPE_DISK: u32 = 0x0001;
    const INVALID_HANDLE_VALUE: isize = -1;

    #[repr(C)]
    #[derive(Default)]
    struct FileTime { low: u32, high: u32 }

    #[repr(C)]
    #[derive(Default)]
    struct ByHandleFileInfo {
        dw_file_attributes: u32,
        ft_creation_time: FileTime,
        ft_last_access_time: FileTime,
        ft_last_write_time: FileTime,
        dw_volume_serial_number: u32,
        n_file_size_high: u32,
        n_file_size_low: u32,
        n_number_of_links: u32,
        n_file_index_high: u32,
        n_file_index_low: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            lp_file_name: *const u16, dw_desired_access: u32, dw_share_mode: u32,
            lp_security_attributes: *const core::ffi::c_void, dw_creation_disposition: u32,
            dw_flags_and_attributes: u32, h_template_file: RawHandle,
        ) -> RawHandle;
        fn GetFileInformationByHandle(h_file: RawHandle, lp_info: *mut ByHandleFileInfo) -> i32;
        fn GetFileType(h_file: RawHandle) -> u32;
    }

    pub(super) fn open_verified_disk_handle(path: &Path) -> Result<(File, u64), String> {
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err(format!("Refusing NUL in Windows path: {}", path.display()));
        }
        wide.push(0);
        // SAFETY: `wide` is NUL-terminated UTF-16; `FILE_FLAG_OPEN_REPARSE_POINT` blocks symlink/junction traversal.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(), GENERIC_READ, FILE_SHARE_ALL, ptr::null(),
                OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, ptr::null_mut(),
            )
        };
        if raw.is_null() || (raw as isize) == INVALID_HANDLE_VALUE {
            return Err(format!("Cannot open {}: {}", path.display(), io::Error::last_os_error()));
        }
        // SAFETY: `raw` is a freshly opened valid Win32 handle; `File` closes it via `CloseHandle` on drop.
        let fh = unsafe { File::from_raw_handle(raw) };
        // SAFETY: `fh` owns a live Win32 handle across this call.
        if unsafe { GetFileType(fh.as_raw_handle()) } != FILE_TYPE_DISK {
            return Err(format!("Refusing non-disk Windows handle: {}", path.display()));
        }
        let mut info = ByHandleFileInfo::default();
        // SAFETY: `fh` is a live disk handle and `info` is a valid aligned `BY_HANDLE_FILE_INFORMATION` struct.
        if unsafe { GetFileInformationByHandle(fh.as_raw_handle(), &mut info) } == 0 {
            return Err(format!("Cannot query Windows handle {}: {}", path.display(), io::Error::last_os_error()));
        }
        if (info.dw_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(format!("Refusing Windows reparse point handle: {}", path.display()));
        }
        if (info.dw_file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 {
            return Err(format!("Not a regular file: {}", path.display()));
        }
        Ok((fh, ((info.n_file_size_high as u64) << 32) | (info.n_file_size_low as u64)))
    }
}

#[cfg(not(any(unix, windows)))]
compile_error!("Unsupported target OS for handle-verified nofollow file I/O");

fn read_regular_bytes_fd_verified_u64(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    #[cfg(unix)]
    let (fh, fd_len) = {
        let sym_meta = std::fs::symlink_metadata(path).map_err(|e| format!("Cannot stat {}: {e}", path.display()))?;
        if sym_meta.file_type().is_symlink() {
            return Err(format!("Refusing symlink: {}", path.display()));
        }
        if !sym_meta.is_file() {
            return Err(format!("Not a regular file: {}", path.display()));
        }
        if sym_meta.len() > max_bytes {
            return Err(format!("FILE_TOO_LARGE:{}: File {} exceeds {} bytes", sym_meta.len(), path.display(), max_bytes));
        }
        let fh = open_regular_nofollow(path).map_err(|e| format!("Cannot open {}: {e}", path.display()))?;
        let fd_meta = fh.metadata().map_err(|e| format!("Cannot stat fd {}: {e}", path.display()))?;
        verify_unix_regular_identity(&sym_meta, &fd_meta)
            .map_err(|e| format!("Handle verification failed on {}: {e}", path.display()))?;
        if fd_meta.len() > max_bytes {
            return Err(format!("FILE_TOO_LARGE:{}: File {} FD size exceeds {} bytes", fd_meta.len(), path.display(), max_bytes));
        }
        (fh, fd_meta.len())
    };

    #[cfg(windows)]
    let (fh, fd_len) = {
        let (fh, sz) = win_nofollow::open_verified_disk_handle(path)?;
        if sz > max_bytes {
            return Err(format!("FILE_TOO_LARGE:{sz}: File {} handle size exceeds {max_bytes} bytes", path.display()));
        }
        (fh, sz)
    };

    let mut buf = Vec::with_capacity((fd_len.min(max_bytes).min(65_536)) as usize);
    fh.take(max_bytes.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| format!("Failed reading {}: {e}", path.display()))?;
    if (buf.len() as u64) > max_bytes {
        return Err(format!("FILE_TOO_LARGE:{}: File {} read exceeds {} bytes", buf.len(), path.display(), max_bytes));
    }
    Ok(buf)
}

/// Read raw bytes from a regular (non-symlink, non-reparse-point) file with leaf `O_NOFOLLOW`/reparse
/// handle verification and `(dev, ino)` TOCTOU identity check (pair with `collect_files_confined` for ancestor walks).
pub fn read_regular_bytes_fd_verified(path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
    read_regular_bytes_fd_verified_u64(path, max_bytes as u64)
}

/// Read UTF-8 text from a regular (non-symlink, non-reparse-point) file with `O_NOFOLLOW`/reparse
/// handle verification, `(dev, ino)` identity check, and bounded size cap (`FILE_TOO_LARGE:<bytes>:...`).
pub fn read_regular_file_fd_verified(path: &Path, max_bytes: u64) -> Result<String, String> {
    let buf = read_regular_bytes_fd_verified_u64(path, max_bytes)?;
    String::from_utf8(buf).map_err(|_| format!("File {} is not valid UTF-8", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct BrokenPipeSink;
    impl Write for BrokenPipeSink {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> { Err(io::Error::from(io::ErrorKind::BrokenPipe)) }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }

    struct PermDeniedSink;
    impl Write for PermDeniedSink {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> { Err(io::Error::new(io::ErrorKind::PermissionDenied, "disk_ro")) }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }

    #[test]
    fn fnv1a_json_escape_raw_json_and_write_outcome_variants() {
        assert!(!ENGINE_VERSION.is_empty());
        assert_eq!(fnv1a_64_hex(b""), "cbf29ce484222325");
        assert_eq!(fnv1a_64_hex(b"foobar"), "85944171f73967e8");
        assert_eq!(json_escape("a\"b\\c\nd\re\tf\u{08}g\u{0C}h\x00i\x1fj🚀"), "a\\\"b\\\\c\\nd\\re\\tf\\bg\\fh\\u0000i\\u001fj🚀");

        let arr = JsonArr::new().str("a\"b").u64(9).raw_json(RawJson("true".into())).obj(JsonObj::new().str("k", "v"));
        let rendered = JsonObj::with_capacity(256)
            .str("tool", "kintsugi\"rs").opt_str("note", None).opt_str("tag", Some("v1"))
            .bool("ok", true).u64("u", 42).usize("sz", 7).i64("delta", -9)
            .f64_2("pct", 88.5).f64_3("ms", 1.25).f64_3("nan_guard", f64::NAN)
            .arr("arr", arr).raw_json("items", RawJson("[1,2]".into())).finish();
        assert!(rendered.contains("\"items\":[1,2]") && rendered.contains("\"nan_guard\":0.000"));
        assert_eq!(write_sink_outcome(Vec::new(), b"ok\n"), WriteOutcome::Written);
        assert_eq!(write_sink_outcome(BrokenPipeSink, b"x\n"), WriteOutcome::BrokenPipe);
        assert!(matches!(write_sink_outcome(PermDeniedSink, b"x\n"), WriteOutcome::IoError(msg) if msg.contains("disk_ro")));
        assert_eq!(write_stdout_outcome(b""), WriteOutcome::Written);
        write_stderr_safe("");
        assert!(try_write_stdout_bytes(b"").is_ok());
    }

    #[test]
    fn read_bytes_and_utf8_fd_verified_nofollow_and_cap() {
        let dir = std::env::temp_dir().join(format!("kintsugi_io_fd_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let (f_txt, f_bin) = (dir.join("ok.txt"), dir.join("raw.bin"));
        std::fs::write(&f_txt, "hello\n").unwrap();
        std::fs::write(&f_bin, [0xffu8, 0x00, 0xfe]).unwrap();
        assert_eq!(read_regular_file_fd_verified(&f_txt, 64).unwrap(), "hello\n");
        assert_eq!(read_regular_bytes_fd_verified(&f_bin, 64).unwrap(), vec![0xff, 0x00, 0xfe]);
        assert!(read_regular_file_fd_verified(&f_bin, 64).is_err());
        assert!(read_regular_bytes_fd_verified(&f_txt, 2).unwrap_err().starts_with("FILE_TOO_LARGE:"));
        #[cfg(unix)]
        {
            let link = dir.join("sym.txt");
            let _ = std::fs::remove_file(&link);
            std::os::unix::fs::symlink(&f_txt, &link).unwrap();
            assert!(open_regular_nofollow(&link).is_err());
            assert!(read_regular_bytes_fd_verified(&link, 64).is_err());
            let _ = std::fs::remove_file(&link);
        }
        let _ = std::fs::remove_file(&f_txt);
        let _ = std::fs::remove_file(&f_bin);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn concurrent_symlink_swap_attempt_is_rejected_without_toctou_leak() {
        use std::sync::{atomic::{AtomicBool, Ordering}, Arc};

        let dir = std::env::temp_dir().join(format!("kintsugi_toctou_race_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let outside_canary = dir.join("outside_canary.txt");
        let slot = dir.join("swapped_slot.txt");
        let stage_reg = dir.join("stage_reg.tmp");
        let stage_sym = dir.join("stage_sym.tmp");
        const CANARY_TAG: &str = "CANARY_OUTSIDE_PAYLOAD";
        const CANARY_BODY: &str = "CANARY_OUTSIDE_PAYLOAD_NEVER_LEAK\n";
        const SAFE_BODY: &str = "SAFE_REGULAR_FILE_PAYLOAD\n";
        const RACE_ITERS: usize = 200;
        std::fs::write(&outside_canary, CANARY_BODY).unwrap();
        std::fs::write(&slot, SAFE_BODY).unwrap();

        let mut ok_seen = 0usize;
        let mut err_seen = 0usize;
        let mut expected_total = RACE_ITERS;

        // Deterministic: reading through a symlink that points outside must always be rejected.
        #[cfg(unix)]
        {
            let direct_link = dir.join("direct_link.txt");
            std::os::unix::fs::symlink(&outside_canary, &direct_link).unwrap();
            match read_regular_file_fd_verified(&direct_link, 4096) {
                Ok(content) => panic!("symlink read must be rejected, got {content:?}"),
                Err(err) => {
                    assert!(!err.contains(CANARY_TAG), "direct symlink error leaked canary: {err}");
                    err_seen += 1;
                }
            }
            expected_total += 1;
            let _ = std::fs::remove_file(&direct_link);
        }

        let stop = Arc::new(AtomicBool::new(false));
        let stop_bg = Arc::clone(&stop);
        let (canary_bg, slot_bg) = (outside_canary.clone(), slot.clone());
        let toggler = std::thread::spawn(move || {
            let mut round = 0usize;
            while !stop_bg.load(Ordering::Relaxed) || round < RACE_ITERS {
                let _ = std::fs::write(&stage_reg, SAFE_BODY);
                let _ = std::fs::rename(&stage_reg, &slot_bg);
                #[cfg(unix)]
                {
                    let _ = std::fs::remove_file(&stage_sym);
                    if std::os::unix::fs::symlink(&canary_bg, &stage_sym).is_ok() {
                        let _ = std::fs::rename(&stage_sym, &slot_bg);
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = (&canary_bg, &stage_sym);
                }
                round += 1;
            }
        });

        for iter in 0..RACE_ITERS {
            match read_regular_file_fd_verified(&slot, 4096) {
                Ok(content) => {
                    assert!(!content.contains(CANARY_TAG), "TOCTOU canary leaked at iter {iter}: {content:?}");
                    assert_eq!(content, SAFE_BODY);
                    ok_seen += 1;
                }
                Err(err) => {
                    assert!(!err.contains(CANARY_TAG), "error leaked canary at iter {iter}: {err}");
                    err_seen += 1;
                }
            }
        }
        stop.store(true, Ordering::Relaxed);
        toggler.join().unwrap();
        assert_eq!(ok_seen + err_seen, expected_total);
        #[cfg(unix)]
        assert!(err_seen >= 1, "symlink swap never produced a rejection (ok_seen={ok_seen})");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn mismatched_dev_ino_identity_is_rejected() {
        let dir = std::env::temp_dir().join(format!("kintsugi_ident_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (file_a, file_b) = (dir.join("a.txt"), dir.join("b.txt"));
        std::fs::write(&file_a, "A\n").unwrap();
        std::fs::write(&file_b, "B\n").unwrap();
        let meta_file_a: std::fs::Metadata = std::fs::symlink_metadata(&file_a).unwrap();
        let meta_file_b: std::fs::Metadata = std::fs::symlink_metadata(&file_b).unwrap();

        assert!(verify_unix_regular_identity(&meta_file_a, &meta_file_a).is_ok());
        let err = verify_unix_regular_identity(&meta_file_a, &meta_file_b).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let fifo = dir.join("pipe.fifo");
        let made_fifo = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .is_ok_and(|s| s.success());
        if made_fifo {
            let fifo_meta = std::fs::symlink_metadata(&fifo).unwrap();
            assert!(!fifo_meta.is_file());
            assert!(verify_unix_regular_identity(&fifo_meta, &fifo_meta).is_err());
            assert!(read_regular_file_fd_verified(&fifo, 64).is_err());
        } else {
            let dir_meta = std::fs::symlink_metadata(&dir).unwrap();
            assert!(!dir_meta.is_file());
            assert!(verify_unix_regular_identity(&dir_meta, &dir_meta).is_err());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn check_bounded_utf8_stdin(raw: Vec<u8>, max_bytes: usize) -> Result<String, String> {
        if raw.len() > max_bytes {
            return Err(format!("FILE_TOO_LARGE:{}: stdin exceeds {max_bytes} bytes", raw.len()));
        }
        String::from_utf8(raw).map_err(|e| format!("stdin is not valid UTF-8 at byte {}", e.utf8_error().valid_up_to()))
    }

    #[test]
    fn bounded_utf8_cap_rejects_split_multibyte_boundary() {
        let text = "aé🚀"; // 1 + 2 + 4 = 7 bytes
        let bytes = text.as_bytes().to_vec();
        assert_eq!(bytes.len(), 7);
        assert_eq!(check_bounded_utf8_stdin(bytes.clone(), 7).unwrap(), text);
        assert!(check_bounded_utf8_stdin(bytes.clone(), 6).unwrap_err().starts_with("FILE_TOO_LARGE:7:"));
        assert!(check_bounded_utf8_stdin(bytes[..2].to_vec(), 7).unwrap_err().contains("byte 1"));
        assert!(check_bounded_utf8_stdin(bytes[..5].to_vec(), 7).unwrap_err().contains("byte 3"));
        assert_eq!(check_bounded_utf8_stdin(Vec::new(), 0).unwrap(), "");

        let dir = std::env::temp_dir().join(format!("kintsugi_utf8_cap_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let f = dir.join("multi.txt");
        std::fs::write(&f, text).unwrap();
        assert!(read_regular_file_fd_verified(&f, 2).unwrap_err().starts_with("FILE_TOO_LARGE:"));
        assert_eq!(read_regular_file_fd_verified(&f, 7).unwrap(), text);
        let _ = std::fs::remove_file(&f);
        let _ = std::fs::remove_dir(&dir);
    }
}
