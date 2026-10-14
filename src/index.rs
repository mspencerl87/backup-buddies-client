// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

//! The client's on-disk index (SQLite, `DATA_DIR/index.sqlite`): the
//! dashboard's Activity card (see activity.rs).
//!
//! It also held what whole-file backups had sent each buddy, until client
//! 0.21.0 made chunked backups the only kind. Those tables are left as they
//! are in an existing index, unused.

use std::path::Path;
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use rusqlite::{params, Connection};

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// One Activity card event (see activity.rs). `details` is a JSON array
/// of strings, shown when the event is expanded.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ActivityEvent {
    pub id: i64,
    pub at: i64,
    pub kind: String,
    pub buddy: Option<String>,
    pub text: String,
    pub details: Vec<String>,
}

pub struct Index {
    conn: Mutex<Connection>,
}

static INDEX: OnceLock<Index> = OnceLock::new();

/// Opens (creating if needed) the index in `data_dir`. Call once at
/// startup.
pub fn open(data_dir: &Path) -> Result<()> {
    if INDEX.get().is_some() {
        return Ok(());
    }
    let index = Index::open_at(&data_dir.join("index.sqlite"))?;
    let _ = INDEX.set(index);
    Ok(())
}

pub fn get() -> &'static Index {
    INDEX.get().expect("index::open must run at startup")
}

/// The index if it's been opened — for callers that also run where it
/// isn't (tests, the `restore` command), like activity::record.
pub fn try_get() -> Option<&'static Index> {
    INDEX.get()
}

impl Index {
    pub fn open_at(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("can't open {}", path.display()))?;
        // WAL: readers (the dashboard) don't block the writer, and a crash
        // mid-write can't corrupt the database.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS activity (
                 id      INTEGER PRIMARY KEY AUTOINCREMENT,
                 at      INTEGER NOT NULL,
                 kind    TEXT NOT NULL,
                 buddy   TEXT,
                 text    TEXT NOT NULL,
                 details TEXT
             );",
        )
        .context("failed to set up the index")?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Adds an Activity event, then trims to the last `keep_days` and at
    /// most `keep_rows` events.
    pub fn add_activity(
        &self,
        kind: &str,
        buddy: Option<&str>,
        text: &str,
        details: Option<&str>,
        keep_days: i64,
        keep_rows: i64,
    ) -> Result<()> {
        self.add_activity_at(now_secs(), kind, buddy, text, details, keep_days, keep_rows)
    }

    #[allow(clippy::too_many_arguments)]
    fn add_activity_at(
        &self,
        at: i64,
        kind: &str,
        buddy: Option<&str>,
        text: &str,
        details: Option<&str>,
        keep_days: i64,
        keep_rows: i64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.prepare_cached("INSERT INTO activity (at, kind, buddy, text, details) VALUES (?1, ?2, ?3, ?4, ?5)")?
            .execute(params![at, kind, buddy, text, details])?;
        conn.prepare_cached(
            "DELETE FROM activity WHERE at < ?1 OR id <= (SELECT MAX(id) FROM activity) - ?2",
        )?
        .execute(params![at - keep_days * 86_400, keep_rows])?;
        Ok(())
    }

    /// The newest `limit` events, optionally only of the given kinds.
    pub fn recent_activity(&self, kinds: &[&str], limit: usize) -> Result<Vec<ActivityEvent>> {
        let conn = self.conn.lock().unwrap();
        let filter = if kinds.is_empty() {
            String::new()
        } else {
            format!("WHERE kind IN ({})", vec!["?"; kinds.len()].join(", "))
        };
        let mut stmt = conn.prepare(&format!(
            "SELECT id, at, kind, buddy, text, details FROM activity {filter} ORDER BY id DESC LIMIT {}",
            limit.min(1000)
        ))?;
        let rows = stmt.query_map(rusqlite::params_from_iter(kinds.iter()), |row| {
            let details: Option<String> = row.get(5)?;
            Ok(ActivityEvent {
                id: row.get(0)?,
                at: row.get(1)?,
                kind: row.get(2)?,
                buddy: row.get(3)?,
                text: row.get(4)?,
                details: details.and_then(|d| serde_json::from_str(&d).ok()).unwrap_or_default(),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_is_newest_first_filtered_and_trimmed() {
        let dir = std::env::temp_dir().join(format!("bb-index-activity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let idx = Index::open_at(&dir.join("index.sqlite")).unwrap();
        let now = now_secs();
        idx.add_activity_at(now - 40 * 86_400, "backup", Some("testb"), "too old", None, 30, 5).unwrap();
        for i in 0..7 {
            let kind = if i % 2 == 0 { "backup" } else { "problem" };
            idx.add_activity_at(now, kind, Some("testb"), &format!("event {i}"), Some(r#"["a.txt"]"#), 30, 5).unwrap();
        }
        let all = idx.recent_activity(&[], 50).unwrap();
        let texts: Vec<&str> = all.iter().map(|e| e.text.as_str()).collect();
        assert_eq!(texts, vec!["event 6", "event 5", "event 4", "event 3", "event 2"], "newest 5 kept, old one gone");
        assert_eq!(all[0].details, vec!["a.txt".to_string()]);
        let problems = idx.recent_activity(&["problem"], 50).unwrap();
        assert!(problems.iter().all(|e| e.kind == "problem") && problems.len() == 2);
        assert_eq!(idx.recent_activity(&[], 2).unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
