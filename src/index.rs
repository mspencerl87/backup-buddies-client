// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

//! The client's on-disk index (SQLite, `DATA_DIR/index.sqlite`).
//!
//! Replaces the per-buddy `manifest-<buddy>.json` files, which were loaded
//! whole into memory and rewritten in full after every file sent — fine for
//! a few hundred files, hopeless for a million. Two tables:
//!
//! - `local_files`: size, modified time and SHA-256 of each file in
//!   BACKUP_DIR, so a scan only re-reads a file when its size or modified
//!   time changed. Shared by all buddies.
//! - `sent`: per buddy, what we last sent them for each path (plaintext
//!   size + hash, and the encrypted size they store) — the old manifest.
//!
//! Existing JSON manifests are imported on first start and renamed to
//! `*.json.migrated`, so nothing is re-sent after upgrading.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentEntry {
    /// Plaintext size and hash of the local file when it was sent.
    pub size: u64,
    pub sha256: String,
    /// Encrypted size stored on the buddy's side — what the dashboard shows
    /// and reconciliation compares against the buddy's own listing.
    pub ciphertext_size: u64,
}

pub struct Index {
    conn: Mutex<Connection>,
}

static INDEX: OnceLock<Index> = OnceLock::new();

/// Opens (creating if needed) the index in `data_dir` and imports any old
/// JSON manifests. Call once at startup.
pub fn open(data_dir: &Path) -> Result<()> {
    if INDEX.get().is_some() {
        return Ok(());
    }
    let index = Index::open_at(&data_dir.join("index.sqlite"))?;
    index.import_json_manifests(data_dir)?;
    let _ = INDEX.set(index);
    Ok(())
}

pub fn get() -> &'static Index {
    INDEX.get().expect("index::open must run at startup")
}

impl Index {
    pub fn open_at(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("can't open {}", path.display()))?;
        // WAL: readers (the dashboard) don't block the writer (backup
        // cycles), and a crash mid-write can't corrupt the database.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS local_files (
                 path     TEXT PRIMARY KEY,
                 size     INTEGER NOT NULL,
                 mtime_ns INTEGER NOT NULL,
                 sha256   TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS sent (
                 buddy           TEXT NOT NULL,
                 path            TEXT NOT NULL,
                 size            INTEGER NOT NULL,
                 sha256          TEXT NOT NULL,
                 ciphertext_size INTEGER NOT NULL,
                 PRIMARY KEY (buddy, path)
             );",
        )
        .context("failed to set up the index")?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn import_json_manifests(&self, data_dir: &Path) -> Result<()> {
        let Ok(entries) = std::fs::read_dir(data_dir) else { return Ok(()) };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(buddy) = name.strip_prefix("manifest-").and_then(|n| n.strip_suffix(".json")) else {
                continue;
            };
            let path = entry.path();
            let manifest: crate::manifest::LegacyManifest = match std::fs::read(&path)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
            {
                Some(m) => m,
                None => {
                    tracing::warn!(path = %path.display(), "old manifest unreadable — skipping import; that buddy's files will be re-checked");
                    continue;
                }
            };
            let count = manifest.entries.len();
            {
                let mut conn = self.conn.lock().unwrap();
                let tx = conn.transaction()?;
                {
                    let mut stmt = tx.prepare(
                        "INSERT OR REPLACE INTO sent (buddy, path, size, sha256, ciphertext_size) VALUES (?1, ?2, ?3, ?4, ?5)",
                    )?;
                    for (rel, e) in &manifest.entries {
                        stmt.execute(params![buddy, rel, e.size as i64, e.sha256, e.ciphertext_size as i64])?;
                    }
                }
                tx.commit()?;
            }
            let done = path.with_extension("json.migrated");
            std::fs::rename(&path, &done).with_context(|| format!("can't rename {}", path.display()))?;
            tracing::info!(buddy, files = count, "imported old manifest into the index");
        }
        Ok(())
    }

    // --- sent (what each buddy holds from us) ---------------------------

    pub fn sent_entries(&self, buddy: &str) -> Result<HashMap<String, SentEntry>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached("SELECT path, size, sha256, ciphertext_size FROM sent WHERE buddy = ?1")?;
        let rows = stmt.query_map(params![buddy], |r| {
            Ok((
                r.get::<_, String>(0)?,
                SentEntry {
                    size: r.get::<_, i64>(1)? as u64,
                    sha256: r.get(2)?,
                    ciphertext_size: r.get::<_, i64>(3)? as u64,
                },
            ))
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// (file count, total encrypted bytes) we've sent this buddy.
    pub fn sent_summary(&self, buddy: &str) -> Result<(usize, u64)> {
        let conn = self.conn.lock().unwrap();
        let (n, bytes): (i64, i64) = conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(ciphertext_size), 0) FROM sent WHERE buddy = ?1",
            params![buddy],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok((n as usize, bytes as u64))
    }

    pub fn record_sent(&self, buddy: &str, path: &str, e: &SentEntry) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.prepare_cached(
            "INSERT OR REPLACE INTO sent (buddy, path, size, sha256, ciphertext_size) VALUES (?1, ?2, ?3, ?4, ?5)",
        )?
        .execute(params![buddy, path, e.size as i64, e.sha256, e.ciphertext_size as i64])?;
        Ok(())
    }

    pub fn forget_sent(&self, buddy: &str, paths: &[String]) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached("DELETE FROM sent WHERE buddy = ?1 AND path = ?2")?;
            for p in paths {
                stmt.execute(params![buddy, p])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    // --- local_files (hash cache for BACKUP_DIR) -------------------------

    /// The stored hash for `path`, if its size and modified time still
    /// match what was recorded — i.e. the file hasn't changed since.
    pub fn cached_hash(&self, path: &str, size: u64, mtime_ns: i64) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        Ok(conn
            .prepare_cached("SELECT sha256 FROM local_files WHERE path = ?1 AND size = ?2 AND mtime_ns = ?3")?
            .query_row(params![path, size as i64, mtime_ns], |r| r.get(0))
            .optional()?)
    }

    pub fn remember_hash(&self, path: &str, size: u64, mtime_ns: i64, sha256: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.prepare_cached(
            "INSERT OR REPLACE INTO local_files (path, size, mtime_ns, sha256) VALUES (?1, ?2, ?3, ?4)",
        )?
        .execute(params![path, size as i64, mtime_ns, sha256])?;
        Ok(())
    }

    /// Drops cached hashes for files no longer in BACKUP_DIR. Only call
    /// after a complete scan (nothing unreadable), or files that merely
    /// couldn't be read this time would lose their entry.
    pub fn prune_hashes(&self, present: &HashSet<&String>) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let gone: Vec<String> = {
            let mut stmt = conn.prepare("SELECT path FROM local_files")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            rows.filter_map(|r| r.ok()).filter(|p| !present.contains(p)).collect()
        };
        if gone.is_empty() {
            return Ok(());
        }
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare_cached("DELETE FROM local_files WHERE path = ?1")?;
            for p in &gone {
                stmt.execute(params![p])?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_old_json_manifest_once_and_tracks_changes() {
        let dir = std::env::temp_dir().join(format!("bb-index-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("manifest-buddyA.json"),
            r#"{"entries":{"a.txt":{"size":5,"sha256":"aa","ciphertext_size":200},
                           "old.txt":{"size":1,"sha256":"bb"}}}"#,
        )
        .unwrap();

        let idx = Index::open_at(&dir.join("index.sqlite")).unwrap();
        idx.import_json_manifests(&dir).unwrap();
        assert!(dir.join("manifest-buddyA.json.migrated").exists());
        let sent = idx.sent_entries("buddyA").unwrap();
        assert_eq!(sent["a.txt"], SentEntry { size: 5, sha256: "aa".into(), ciphertext_size: 200 });
        assert_eq!(sent["old.txt"].ciphertext_size, 0, "missing field defaults like before");
        assert_eq!(idx.sent_summary("buddyA").unwrap(), (2, 200));
        assert!(idx.sent_entries("buddyB").unwrap().is_empty());

        // Second import is a no-op (file already renamed).
        idx.import_json_manifests(&dir).unwrap();
        assert_eq!(idx.sent_summary("buddyA").unwrap().0, 2);

        idx.forget_sent("buddyA", &["old.txt".to_string()]).unwrap();
        idx.record_sent("buddyA", "b.txt", &SentEntry { size: 9, sha256: "cc".into(), ciphertext_size: 300 }).unwrap();
        assert_eq!(idx.sent_summary("buddyA").unwrap(), (2, 500));

        // Hash cache only hits when size and mtime both still match.
        idx.remember_hash("a.txt", 5, 111, "aa").unwrap();
        assert_eq!(idx.cached_hash("a.txt", 5, 111).unwrap().as_deref(), Some("aa"));
        assert_eq!(idx.cached_hash("a.txt", 5, 112).unwrap(), None);
        assert_eq!(idx.cached_hash("a.txt", 6, 111).unwrap(), None);
        let keep = "b.txt".to_string();
        idx.prune_hashes(&[&keep].into_iter().collect()).unwrap();
        assert_eq!(idx.cached_hash("a.txt", 5, 111).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
