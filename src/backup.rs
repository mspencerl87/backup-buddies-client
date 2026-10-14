// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

//! What every backup cycle shares, whatever does the sending (chunked.rs):
//! the scan of BACKUP_DIR, the cycle's stats, and its live progress.

use std::{
    collections::HashMap,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Context, Result};
use serde::Serialize;

use crate::netinfo::{self, ConnectionQuality};
use crate::protocol::{self, SyncRequest};

/// One path that failed to back up this cycle, with a human-readable
/// reason when we have one.
#[derive(Debug, Clone)]
pub struct FailedFile {
    pub path: String,
    pub reason: Option<&'static str>,
}

/// What one backup cycle actually did, including transfer metrics — not
/// just file counts. `duration_ms`, the connection and `traffic` come off
/// the connection itself, letting the dashboard show a real transfer rate
/// for the cycle instead of just "sent 3 files". Zeroed/None when the
/// cycle found nothing to do and never opened a connection at all.
#[derive(Debug, Clone, Default)]
pub struct BackupCycleStats {
    pub files_sent: usize,
    pub files_deleted: usize,
    /// What the new snapshot added to the buddy's repository (packed and
    /// encrypted), not the size of the files that changed.
    pub bytes_sent: u64,
    pub duration_ms: u64,
    pub connection: Option<ConnectionQuality>,
    // bytes_sent split by the paths that actually carried it, for the
    // relay/direct totals (and relay billing). None when nothing connected.
    pub traffic: Option<netinfo::ByteSplit>,
    // Files the scan couldn't read: not fatal (everything else is still
    // backed up), but worth the dashboard calling out, since one that
    // stays unreadable fails every cycle.
    pub files_failed: usize,
    // A capped sample of which paths failed, with a reason.
    pub failed_paths: Vec<FailedFile>,
    // For the dashboard's Activity card: which files went out and which
    // were removed (capped, see chunked.rs's ACTIVITY_PATHS).
    pub sent_paths: Vec<String>,
    pub deleted_paths: Vec<String>,
}

/// Live progress of one buddy's backup cycle while it runs, so a long first
/// backup shows signs of life on the dashboard instead of "no cycle yet"
/// for hours. Only present while a cycle is running; removed when it ends
/// (success or not), at which point the normal last-cycle record takes over.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CycleProgress {
    /// "checking" (scanning for changes) or "sending" (backing up).
    pub phase: &'static str,
    pub files_total: usize,
    pub bytes_total: u64,
    /// Bytes rustic has read so far (filled in by `snapshot`). A backup
    /// reads every file but sends only new chunks, so this is how far
    /// along it is, not what's been sent.
    pub bytes_read: u64,
    pub started_unix: u64,
    /// When the sending phase started — the rate and time left are
    /// measured from here, not from the start of checking.
    pub sending_started_unix: Option<u64>,
    /// This device's clock when the snapshot was taken, so the browser
    /// measures elapsed time against the same clock (no skew).
    pub now_unix: u64,
    #[serde(skip)]
    counter: Arc<AtomicU64>,
}

impl CycleProgress {
    /// A copy with `bytes_read`/`now_unix` filled in from the live counter.
    pub fn snapshot(&self) -> CycleProgress {
        let mut copy = self.clone();
        copy.bytes_read = self.counter.load(Ordering::Relaxed).min(self.bytes_total);
        copy.now_unix = crate::dashboard::unix_now();
        copy
    }
}

/// In-flight cycle progress per buddy node id — shared with the dashboard.
pub type CycleProgressBook = Arc<Mutex<HashMap<String, CycleProgress>>>;

/// Updates one buddy's entry in a `CycleProgressBook`, and removes it when
/// dropped, so an early return or error never leaves a stuck progress bar.
pub(crate) struct ProgressTracker {
    book: Option<CycleProgressBook>,
    node_id: String,
    pub(crate) counter: Arc<AtomicU64>,
}

impl ProgressTracker {
    pub(crate) fn new(book: Option<&CycleProgressBook>, node_id: &str) -> Self {
        let counter = Arc::new(AtomicU64::new(0));
        if let Some(book) = book {
            book.lock().unwrap().insert(
                node_id.to_string(),
                CycleProgress {
                    phase: "checking",
                    started_unix: crate::dashboard::unix_now(),
                    counter: counter.clone(),
                    ..Default::default()
                },
            );
        }
        Self { book: book.cloned(), node_id: node_id.to_string(), counter }
    }

    pub(crate) fn update(&self, f: impl FnOnce(&mut CycleProgress)) {
        if let Some(book) = &self.book
            && let Some(p) = book.lock().unwrap().get_mut(&self.node_id)
        {
            f(p);
        }
    }
}

impl Drop for ProgressTracker {
    fn drop(&mut self) {
        if let Some(book) = &self.book {
            book.lock().unwrap().remove(&self.node_id);
        }
    }
}

/// Asks the buddy which protocol version it speaks. A client older than
/// 0.5.0 can't parse the question and drops the stream, which reads as an
/// error here — that *is* the answer (version 1).
pub(crate) async fn buddy_protocol_version(conn: &iroh::endpoint::Connection) -> u32 {
    let ask = async {
        let (mut send, mut recv) = conn.open_bi().await?;
        protocol::write_frame(&mut send, &SyncRequest::Hello).await?;
        send.finish()?;
        let resp: protocol::HelloResponse = protocol::read_frame(&mut recv).await?;
        anyhow::Ok(resp.protocol_version)
    };
    match tokio::time::timeout(std::time::Duration::from_secs(15), ask).await {
        Ok(Ok(v)) => v,
        _ => 1,
    }
}

/// File count, total bytes and excluded count (files plus skipped folders)
/// under `backup_dir` right now — for the dashboard's "This Device" panel.
/// A plain re-scan, since this is meant to show what's actually sitting in
/// the directory, independent of whether it's been backed up to any
/// particular buddy yet.
pub async fn local_backup_summary(backup_dir: &Path) -> Result<(usize, u64, usize)> {
    let scan = scan_local_files(backup_dir).await?;
    let total_bytes = scan.files.iter().map(|f| f.size).sum();
    Ok((scan.files.len(), total_bytes, scan.excluded))
}

/// One file found in BACKUP_DIR. `mtime_ns` is its modified time in
/// nanoseconds since the epoch (-1 if unavailable), for chunked.rs's
/// change fingerprint.
pub(crate) struct LocalFile {
    pub(crate) rel_path: String,
    pub(crate) size: u64,
    pub(crate) mtime_ns: i64,
}

/// What a scan of BACKUP_DIR found: the files it could see, plus anything
/// it couldn't open (relative paths). Unreadable entries matter: a folder
/// the client isn't allowed to open looks exactly like a folder that was
/// deleted, so callers must not treat "not in `files`" as "gone" while
/// `unreadable` is non-empty. Excluded files are left out of `files`, so
/// one that was backed up before is left out of the next snapshot.
pub(crate) struct LocalScan {
    pub(crate) files: Vec<LocalFile>,
    pub(crate) unreadable: Vec<String>,
    /// Files and skipped folders the exclude list kept out.
    pub(crate) excluded: usize,
    pub(crate) rules: crate::excludes::Rules,
}

pub(crate) fn rel_to(backup_dir: &Path, abs_path: &Path) -> String {
    abs_path
        .strip_prefix(backup_dir)
        .unwrap_or(abs_path)
        .to_string_lossy()
        .replace('\\', "/") // normalize separators in case this ever runs on Windows
}

// Metadata only — no file contents are read here. Runs on a blocking
// thread, since walking a large folder can take a while. The exclude list
// is re-read each time, so edits apply on the next cycle.
pub(crate) async fn scan_local_files(backup_dir: &Path) -> Result<LocalScan> {
    let backup_dir = backup_dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let rules = crate::excludes::Rules::load()?;
        Ok(scan_local_files_blocking(&backup_dir, rules))
    })
    .await
    .context("folder scan task failed")?
}

fn scan_local_files_blocking(backup_dir: &Path, rules: crate::excludes::Rules) -> LocalScan {
    let mut out = Vec::new();
    let mut unreadable = Vec::new();
    // A Cell since the folder filter below counts into it too.
    let excluded = std::cell::Cell::new(0usize);
    // Excluded folders aren't even opened (when no `!` line could bring
    // something back from inside one): faster for things like .zfs or
    // node_modules, and a locked "System Volume Information" no longer
    // pauses deletions as unreadable.
    let skip_folders = rules.can_skip_folders();
    let walk = walkdir::WalkDir::new(backup_dir).follow_links(false).into_iter().filter_entry(|e| {
        if !skip_folders || e.depth() == 0 || !e.file_type().is_dir() {
            return true;
        }
        if rules.is_excluded(&rel_to(backup_dir, e.path())) {
            excluded.set(excluded.get() + 1);
            return false;
        }
        true
    });
    for entry in walk {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                // Permission denied on a folder (or a file vanishing mid-walk).
                // Recorded rather than skipped silently — see LocalScan.
                let path = err.path().map(|p| rel_to(backup_dir, p)).unwrap_or_default();
                tracing::warn!(path = %path, %err, "can't read part of BACKUP_DIR");
                unreadable.push(path);
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let rel_path = rel_to(backup_dir, entry.path());
        if rules.is_excluded(&rel_path) {
            excluded.set(excluded.get() + 1);
            continue;
        }
        let meta = entry.metadata().ok();
        let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
        let mtime_ns = meta
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(-1);
        out.push(LocalFile { rel_path, size, mtime_ns });
    }
    LocalScan { files: out, unreadable, excluded: excluded.get(), rules }
}

/// True when BACKUP_DIR scanned completely (nothing unreadable) yet came
/// back empty while the buddy holds files from it — the signature of a
/// drive that isn't mounted rather than a real "delete everything".
pub(crate) fn looks_like_missing_drive(local_files: usize, unreadable: usize, backed_up: usize) -> bool {
    local_files == 0 && unreadable == 0 && backed_up > 0
}

/// ALLOW_EMPTY_BACKUP_DIR=true lets a cycle back up an empty folder where
/// the last snapshot had files. Off by default — see the empty-folder guard
/// in chunked.rs's run_chunked_cycle.
pub fn allow_empty_backup_dir() -> bool {
    matches!(
        std::env::var("ALLOW_EMPTY_BACKUP_DIR").map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Ok("1" | "true" | "yes")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bb-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn empty_folder_with_backed_up_files_looks_like_missing_drive() {
        assert!(looks_like_missing_drive(0, 0, 12));
        assert!(!looks_like_missing_drive(0, 0, 0), "a fresh, empty folder is fine");
        assert!(!looks_like_missing_drive(3, 0, 12), "some files present: ordinary deletions");
        assert!(!looks_like_missing_drive(0, 1, 12), "unreadable is handled by pausing deletions instead");
    }

    #[test]
    fn excluded_files_and_folders_are_left_out() {
        let dir = tmp("excludes");
        std::fs::create_dir_all(dir.join("mail")).unwrap();
        std::fs::create_dir_all(dir.join("photos/.zfs/snapshot")).unwrap();
        std::fs::write(dir.join("mail/inbox.PST"), b"x").unwrap();
        std::fs::write(dir.join("mail/notes.txt"), b"x").unwrap();
        std::fs::write(dir.join("photos/a.jpg"), b"x").unwrap();
        std::fs::write(dir.join("photos/.zfs/snapshot/a.jpg"), b"x").unwrap();
        std::fs::write(dir.join("photos/a.iso"), b"x").unwrap();

        let rules = crate::excludes::Rules::build("*.iso", true).unwrap();
        let scan = scan_local_files_blocking(&dir, rules);
        let _ = std::fs::remove_dir_all(&dir);
        let mut names: Vec<&str> = scan.files.iter().map(|f| f.rel_path.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["mail/notes.txt", "photos/a.jpg"]);
        // inbox.PST, a.iso, and the .zfs folder (skipped whole).
        assert_eq!(scan.excluded, 3);
    }

    // Root ignores permissions, so this only proves anything when run as a
    // normal user; as root it returns early rather than giving a false pass.
    #[tokio::test]
    async fn unreadable_folder_is_reported_not_treated_as_deleted() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("scan");
        std::fs::write(dir.join("a.txt"), b"a").unwrap();
        let locked = dir.join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::write(locked.join("b.txt"), b"b").unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let readable_anyway = std::fs::read_dir(&locked).is_ok();

        let scan = scan_local_files(&dir).await.unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        if readable_anyway {
            eprintln!("running as root: permission check skipped");
            return;
        }
        let names: Vec<&str> = scan.files.iter().map(|f| f.rel_path.as_str()).collect();
        assert_eq!(names, vec!["a.txt"]);
        assert_eq!(scan.unreadable, vec!["locked".to_string()]);
    }
}
