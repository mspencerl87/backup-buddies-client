// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

//! The dashboard's Activity card: a plain-language record of what this
//! client did and what happened to it, newest first.
//!
//! Events are things that happened, not the steady state: files sent or
//! removed, a buddy going unreachable and coming back, files a buddy
//! stored with us, restores, exclude-list and login changes, startup and
//! updates. The "nothing new" check every 30 s and every ping are left
//! out — they'd bury everything else, and the buddy cards already show
//! them live. A buddy that stays broken is one event when it breaks and
//! one when it recovers, not one per cycle.
//!
//! Events are kept in the index (survive restarts), trimmed to
//! KEEP_DAYS / KEEP_ROWS. The raw log tab is separate: the last RAW_LINES
//! lines of the normal log, captured in memory by RawLogWriter.

use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
};

pub const KEEP_DAYS: i64 = 30;
pub const KEEP_ROWS: i64 = 1000;
const MAX_DETAILS: usize = 50;
const RAW_LINES: usize = 300;

/// Kinds, as stored and as the dashboard's filter chips group them:
/// Backups = backup, incoming, restore; Problems = problem; Security =
/// security, settings. "buddy" (came back online) and "client" (started,
/// update available) only show under All.
pub mod kind {
    pub const BACKUP: &str = "backup";
    pub const PROBLEM: &str = "problem";
    pub const BUDDY: &str = "buddy";
    pub const INCOMING: &str = "incoming";
    pub const RESTORE: &str = "restore";
    pub const SETTINGS: &str = "settings";
    pub const SECURITY: &str = "security";
    pub const CLIENT: &str = "client";
}

/// Buddy node id → the label people know them by (from the API's buddy
/// list, kept current by main.rs's poll loop).
static LABELS: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

pub fn set_label(node_id: &str, label: &str) {
    LABELS.lock().unwrap().get_or_insert_with(HashMap::new).insert(node_id.to_string(), label.to_string());
}

/// The buddy's label, or a short node id before the first API poll.
pub fn label(node_id: &str) -> String {
    LABELS
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|m| m.get(node_id).cloned())
        .unwrap_or_else(|| format!("{}…", &node_id[..node_id.len().min(10)]))
}

pub fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 { format!("{n} B") } else { format!("{value:.1} {}", UNITS[unit]) }
}

pub fn plural(n: usize, one: &str) -> String {
    if n == 1 { format!("1 {one}") } else { format!("{n} {one}s") }
}

/// Adds an event. `buddy` is the label shown next to it (None for events
/// about this device). Never fails the caller: an event that can't be
/// stored is only worth a debug line.
pub fn record(kind: &str, buddy: Option<&str>, text: impl Into<String>, mut details: Vec<String>) {
    let Some(idx) = crate::index::try_get() else { return };
    if details.len() > MAX_DETAILS {
        let more = details.len() - MAX_DETAILS;
        details.truncate(MAX_DETAILS);
        details.push(format!("…and {more} more"));
    }
    let details = if details.is_empty() { None } else { serde_json::to_string(&details).ok() };
    if let Err(err) = idx.add_activity(kind, buddy, &text.into(), details.as_deref(), KEEP_DAYS, KEEP_ROWS) {
        tracing::debug!(?err, "couldn't record an activity event");
    }
}

/// Last known health per buddy, so a broken buddy is one event when it
/// breaks and one when it recovers rather than one every cycle.
static HEALTH: Mutex<Option<HashMap<String, bool>>> = Mutex::new(None);

/// Called with every cycle's verdict (backup or ping) for a buddy.
pub fn buddy_health(node_id: &str, label: &str, ok: bool, detail: &str, path: Option<&str>) {
    let previous = HEALTH.lock().unwrap().get_or_insert_with(HashMap::new).insert(node_id.to_string(), ok);
    match (previous, ok) {
        // Also on the first cycle after a start: a buddy that's broken
        // from the outset is worth saying so.
        (Some(true) | None, false) => record(kind::PROBLEM, Some(label), capitalize(detail), Vec::new()),
        (Some(false), true) => {
            let via = path.map(|p| format!(" ({p})")).unwrap_or_default();
            record(kind::BUDDY, Some(label), format!("Working again{via}"), Vec::new())
        }
        _ => {}
    }
}

/// What one buddy did on one incoming connection, summed and recorded as
/// one event when they disconnect (a backup cycle of 500 files is one
/// line, not 500).
#[derive(Default)]
struct Tally {
    stored: usize,
    stored_bytes: u64,
    deleted: usize,
    fetched: usize,
    fetched_bytes: u64,
    purged: usize,
}

static INCOMING: Mutex<Option<HashMap<String, Tally>>> = Mutex::new(None);

fn tally(node_id: &str, f: impl FnOnce(&mut Tally)) {
    f(INCOMING.lock().unwrap().get_or_insert_with(HashMap::new).entry(node_id.to_string()).or_default());
}

pub fn incoming_stored(node_id: &str, bytes: u64) {
    tally(node_id, |t| {
        t.stored += 1;
        t.stored_bytes += bytes;
    });
}

pub fn incoming_deleted(node_id: &str) {
    tally(node_id, |t| t.deleted += 1);
}

pub fn incoming_fetched(node_id: &str, bytes: u64) {
    tally(node_id, |t| {
        t.fetched += 1;
        t.fetched_bytes += bytes;
    });
}

pub fn incoming_purged(node_id: &str) {
    tally(node_id, |t| t.purged += 1);
}

/// Records what `node_id` did over the connection that just closed.
pub fn flush_incoming(node_id: &str) {
    let Some(t) = INCOMING.lock().unwrap().as_mut().and_then(|m| m.remove(node_id)) else { return };
    let who = label(node_id);
    let mut parts = Vec::new();
    if t.stored > 0 {
        parts.push(format!("stored {} ({}) with you", plural(t.stored, "file"), fmt_bytes(t.stored_bytes)));
    }
    if t.deleted > 0 {
        parts.push(format!("deleted {}", plural(t.deleted, "file")));
    }
    if t.purged > 0 {
        parts.push(format!("permanently removed the kept copies of {}", plural(t.purged, "file")));
    }
    if !parts.is_empty() {
        record(kind::INCOMING, Some(&who), capitalize(&parts.join(", ")), Vec::new());
    }
    if t.fetched > 0 {
        record(
            kind::INCOMING,
            Some(&who),
            format!("Restored {} ({}) from what you hold for them", plural(t.fetched, "file"), fmt_bytes(t.fetched_bytes)),
            Vec::new(),
        );
    }
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// The last RAW_LINES log lines, as `docker compose logs` shows them
/// (without colours), for the Activity card's Raw log tab.
static RAW: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

pub fn raw_log() -> Vec<String> {
    RAW.lock().unwrap().iter().cloned().collect()
}

/// A second log output (next to stdout) that keeps recent lines in memory.
/// tracing's fmt layer writes each event in one go, so each write is one
/// or more whole lines.
pub struct RawLogWriter;

impl std::io::Write for RawLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        let mut raw = RAW.lock().unwrap();
        for line in text.lines().filter(|l| !l.is_empty()) {
            if raw.len() == RAW_LINES {
                raw.pop_front();
            }
            raw.push_back(line.to_string());
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RawLogWriter {
    type Writer = RawLogWriter;
    fn make_writer(&'a self) -> Self::Writer {
        RawLogWriter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_and_plurals() {
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(429_212_135), "409.3 MB");
        assert_eq!(fmt_bytes(3 << 30), "3.0 GB");
        assert_eq!(plural(1, "file"), "1 file");
        assert_eq!(plural(3, "file"), "3 files");
    }

    #[test]
    fn raw_log_keeps_the_newest_lines() {
        use std::io::Write;
        let mut w = RawLogWriter;
        for i in 0..RAW_LINES + 5 {
            w.write_all(format!("line {i}\n").as_bytes()).unwrap();
        }
        let lines = raw_log();
        assert_eq!(lines.len(), RAW_LINES);
        assert_eq!(lines.last().unwrap(), &format!("line {}", RAW_LINES + 4));
    }

    #[test]
    fn incoming_tally_adds_up_per_buddy() {
        incoming_stored("tally-test-buddy", 100);
        incoming_stored("tally-test-buddy", 50);
        incoming_deleted("tally-test-buddy");
        let guard = INCOMING.lock().unwrap();
        let t = &guard.as_ref().unwrap()["tally-test-buddy"];
        assert_eq!((t.stored, t.stored_bytes, t.deleted), (2, 150, 1));
    }
}
