//! Read-Only Memory & Historical Backup Integrity Verifier (`memories-verify`).
//!
//! Hardened with `O_NOFOLLOW` + `(dev, ino)` FD-verified reads (`read_regular_bytes_fd_verified`),
//! honest non-sandboxed reporting (`os_sandbox_enforced: false`), and bounded recursive traversal.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::io_json::{fnv1a_64, read_regular_bytes_fd_verified, JsonObj, ENGINE_VERSION, FNV1A_64_INIT};
use crate::json_dom::parse_json_value;
use crate::policy::sha256_hex;

pub const MEMORIES_ENFORCEMENT_MODE: &str = "unprivileged_readonly_verification";
pub const MEMORIES_READ_ONLY_BEHAVIOR: &str = "unprivileged_open_rdonly_no_mutation";
const MAX_MEMORY_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_MEMORY_TREE_DEPTH: usize = 8;
const MAX_MEMORY_TREE_FILES: usize = 10_000;

#[derive(Debug, Clone)]
pub struct MemoriesVerifyReport {
    pub ok: bool,
    pub read_only_behavior: &'static str,
    pub os_sandbox_enforced: bool,
    pub enforcement_mode: &'static str,
    pub workspace_root: String,
    pub memories_index_exists: bool,
    pub memories_index_bytes: u64,
    pub memories_index_fnv64: String,
    pub memories_index_sha256: String,
    pub lessons_count: usize,
    pub archive_files_count: usize,
    pub changelogs_count: usize,
    pub backups_dirs_count: usize,
    pub symlinks_detected: usize,
    pub unreadable_files: usize,
    pub empty_or_corrupt_files: usize,
    pub elapsed_ms: f64,
    pub status: &'static str,
}

#[derive(Default)]
struct IntegrityCounters {
    symlinks: usize,
    unreadable: usize,
    corrupt: usize,
    files_visited: usize,
    #[cfg(unix)]
    visited_inodes: BTreeSet<(u64, u64)>,
}

impl IntegrityCounters {
    fn verify_file(&mut self, path: &Path) -> Option<Vec<u8>> {
        if self.files_visited >= MAX_MEMORY_TREE_FILES {
            self.unreadable += 1;
            return None;
        }
        self.files_visited += 1;
        let bytes = match read_regular_bytes_fd_verified(path, MAX_MEMORY_FILE_BYTES) {
            Ok(b) => b,
            Err(err) => {
                let lower = err.to_ascii_lowercase();
                if lower.contains("symlink") || lower.contains("reparse") || lower.contains("toctou") {
                    self.symlinks += 1;
                } else {
                    self.unreadable += 1;
                }
                return None;
            }
        };
        if bytes.is_empty() {
            self.corrupt += 1;
            return Some(bytes);
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
        let is_bad = match ext.as_str() {
            "json" => std::str::from_utf8(&bytes).map_or(true, |s| parse_json_value(s.trim()).is_err()),
            "jsonl" => std::str::from_utf8(&bytes).map_or(true, |s| {
                s.lines().filter(|l| !l.trim().is_empty()).any(|l| parse_json_value(l.trim()).is_err())
            }),
            "md" | "markdown" | "txt" | "kml" | "toml" | "yaml" | "yml" | "" => std::str::from_utf8(&bytes).is_err(),
            _ => false,
        };
        if is_bad { self.corrupt += 1; }
        Some(bytes)
    }

    fn enter_dir_checked(&mut self, dir: &Path) -> Option<Vec<PathBuf>> {
        let dm = match fs::symlink_metadata(dir) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(_) => { self.unreadable += 1; return None; }
        };
        if dm.file_type().is_symlink() { self.symlinks += 1; return None; }
        if !dm.is_dir() { return None; }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !self.visited_inodes.insert((dm.dev(), dm.ino())) { return None; }
        }
        let Ok(entries) = fs::read_dir(dir) else { self.unreadable += 1; return None; };
        let mut paths = Vec::new();
        for res_entry in entries {
            match res_entry { Ok(e) => paths.push(e.path()), Err(_) => self.unreadable += 1 }
        }
        paths.sort();
        Some(paths)
    }

    fn visit_shallow_dir(&mut self, dir: &Path, mut on_entry: impl FnMut(&mut Self, PathBuf, fs::Metadata)) {
        let Some(paths) = self.enter_dir_checked(dir) else { return };
        for p in paths {
            match fs::symlink_metadata(&p) {
                Ok(m) if m.file_type().is_symlink() => self.symlinks += 1,
                Ok(m) => on_entry(self, p, m),
                Err(_) => self.unreadable += 1,
            }
        }
    }

    fn visit_tree_no_symlink(
        &mut self,
        dir: &Path,
        depth: usize,
        on_entry: &mut dyn FnMut(&mut Self, usize, &Path, &fs::Metadata),
    ) {
        if depth > MAX_MEMORY_TREE_DEPTH { self.unreadable += 1; return; }
        let Some(paths) = self.enter_dir_checked(dir) else { return };
        for p in paths {
            match fs::symlink_metadata(&p) {
                Ok(m) if m.file_type().is_symlink() => self.symlinks += 1,
                Ok(m) if m.is_dir() => {
                    on_entry(self, depth, &p, &m);
                    self.visit_tree_no_symlink(&p, depth + 1, on_entry);
                }
                Ok(m) => on_entry(self, depth, &p, &m),
                Err(_) => self.unreadable += 1,
            }
        }
    }
}

pub fn verify_memories_readonly(workspace_root: &Path) -> MemoriesVerifyReport {
    let t0 = Instant::now();
    let mem_dir = workspace_root.join(".agents").join("memories");
    let (index_path, lessons_dir, archive_dir) = (mem_dir.join("INDEX.md"), mem_dir.join("lessons"), mem_dir.join("archive"));
    let harness_dir = workspace_root.join(".agents").join("harness");
    let backups_dir = harness_dir.join("backups");

    let mut ctr = IntegrityCounters::default();
    let (index_exists, index_bytes, index_fnv, index_sha256) = match fs::symlink_metadata(&index_path) {
        Ok(m) if m.file_type().is_symlink() => {
            ctr.symlinks += 1;
            (false, 0, "SYMLINK_FORBIDDEN".to_string(), "SYMLINK_FORBIDDEN".to_string())
        }
        Ok(m) if m.is_file() => match ctr.verify_file(&index_path) {
            Some(b) => (true, b.len() as u64, format!("{:016x}", fnv1a_64(&b, FNV1A_64_INIT)), sha256_hex(&b)),
            None => (true, m.len(), "UNREADABLE".to_string(), "UNREADABLE".to_string()),
        },
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            ctr.unreadable += 1;
            (false, 0, "UNREADABLE".to_string(), "UNREADABLE".to_string())
        }
        _ => (false, 0, "MISSING".to_string(), "MISSING".to_string()),
    };

    ctr.visit_shallow_dir(&mem_dir, |c, p, m| {
        if p != index_path && p != lessons_dir && p != archive_dir && m.is_file() { let _ = c.verify_file(&p); }
    });

    let mut lessons_count = 0usize;
    ctr.visit_tree_no_symlink(&lessons_dir, 0, &mut |c, _, p, m| {
        if m.is_file() {
            if p.extension().and_then(|e| e.to_str()) == Some("md") { lessons_count += 1; }
            let _ = c.verify_file(p);
        }
    });

    let mut archive_files_count = 0usize;
    ctr.visit_tree_no_symlink(&archive_dir, 0, &mut |c, _, p, m| {
        if m.is_file() { archive_files_count += 1; let _ = c.verify_file(p); }
    });

    let mut changelogs_count = 0usize;
    ctr.visit_shallow_dir(&harness_dir, |c, p, m| {
        let is_cl = p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("CHANGELOG") && n.ends_with(".md"));
        if is_cl && m.is_file() && c.verify_file(&p).is_some_and(|b| !b.is_empty()) { changelogs_count += 1; }
    });

    let mut backups_dirs_count = 0usize;
    ctr.visit_tree_no_symlink(&backups_dir, 0, &mut |c, depth, p, m| {
        if depth == 0 && m.is_dir() { backups_dirs_count += 1; } else if m.is_file() { let _ = c.verify_file(p); }
    });

    let ok = index_exists && index_bytes > 1024 && lessons_count > 0 && ctr.symlinks == 0 && ctr.unreadable == 0 && ctr.corrupt == 0;
    let status = if ok { "PASS_ZERO_DATA_LOSS_VERIFIED" } else { "FAIL_MEMORIES_INTEGRITY_CHECK" };

    MemoriesVerifyReport {
        ok,
        read_only_behavior: MEMORIES_READ_ONLY_BEHAVIOR,
        os_sandbox_enforced: false,
        enforcement_mode: MEMORIES_ENFORCEMENT_MODE,
        workspace_root: workspace_root.to_string_lossy().to_string(),
        memories_index_exists: index_exists, memories_index_bytes: index_bytes,
        memories_index_fnv64: index_fnv, memories_index_sha256: index_sha256,
        lessons_count, archive_files_count, changelogs_count, backups_dirs_count,
        symlinks_detected: ctr.symlinks, unreadable_files: ctr.unreadable, empty_or_corrupt_files: ctr.corrupt,
        elapsed_ms: (t0.elapsed().as_micros() as f64) / 1000.0, status,
    }
}

pub fn render_memories_verify_json(rep: &MemoriesVerifyReport) -> String {
    JsonObj::with_capacity(560)
        .bool("ok", rep.ok)
        .str("read_only_behavior", rep.read_only_behavior)
        .bool("os_sandbox_enforced", rep.os_sandbox_enforced)
        .str("enforcement_mode", rep.enforcement_mode).str("engine", "kintsugi-rs").str("engine_version", ENGINE_VERSION)
        .str("workspace_root", &rep.workspace_root).bool("memories_index_exists", rep.memories_index_exists)
        .u64("memories_index_bytes", rep.memories_index_bytes).str("memories_index_fnv64", &rep.memories_index_fnv64)
        .str("memories_index_sha256", &rep.memories_index_sha256).usize("lessons_count", rep.lessons_count)
        .usize("archive_files_count", rep.archive_files_count).usize("changelogs_count", rep.changelogs_count)
        .usize("backups_dirs_count", rep.backups_dirs_count).usize("symlinks_detected", rep.symlinks_detected)
        .usize("unreadable_files", rep.unreadable_files).usize("empty_or_corrupt_files", rep.empty_or_corrupt_files)
        .f64_3("elapsed_ms", rep.elapsed_ms).str("status", rep.status)
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_recursive_nested_trees_honest_readonly_fields_and_corruption() {
        let uniq = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let ws = std::env::temp_dir().join(format!("kintsugi_mem_rec_{}_{uniq}", std::process::id()));
        let (deep_lessons, deep_archive, deep_backups) = (
            ws.join(".agents/memories/lessons/2026/q4"),
            ws.join(".agents/memories/archive/s1/s2"),
            ws.join(".agents/harness/backups/snap_01/nested"),
        );
        for d in [&deep_lessons, &deep_archive, &deep_backups] { fs::create_dir_all(d).unwrap(); }
        let idx_body = "# Memory Index\n".to_string() + &"Verified entry line.\n".repeat(60);
        fs::write(ws.join(".agents/memories/INDEX.md"), &idx_body).unwrap();
        fs::write(deep_lessons.join("L001.md"), "# Lesson 1\nAlways pin SHA-256.\n").unwrap();
        fs::write(deep_archive.join("meta.json"), "{\"ok\":true}").unwrap();
        fs::write(deep_backups.join("bak.json"), "{\"snap\":1}").unwrap();

        let ok_rep = verify_memories_readonly(&ws);
        assert!(ok_rep.ok && !ok_rep.os_sandbox_enforced && ok_rep.read_only_behavior == "unprivileged_open_rdonly_no_mutation");
        let rendered = render_memories_verify_json(&ok_rep);
        assert!(rendered.contains("\"read_only_behavior\":\"unprivileged_open_rdonly_no_mutation\"") && !rendered.contains("read_only_enforced"));

        fs::write(deep_backups.join("corrupt.json"), "{broken_nested_backup").unwrap();
        assert!(!verify_memories_readonly(&ws).ok);
        let _ = fs::remove_dir_all(&ws);
    }
}
