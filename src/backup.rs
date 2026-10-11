// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Context, Result};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::index::{self, SentEntry};
use crate::netinfo::{self, ConnectionQuality};
use crate::protocol::{self, PutRejectReason, SyncAck, SyncRequest};

/// One path that failed to back up this cycle, with a human-readable
/// reason when we have one. `reason` is `Some` only when the buddy told us
/// *why* via a STOP_SENDING code (see protocol::PutRejectReason) — any
/// other failure (connection drop, local read error, a delete that
/// failed) still shows up here, just without a specific explanation
/// beyond "failed to sync", since those aren't the buddy actively
/// rejecting the file.
#[derive(Debug, Clone)]
pub struct FailedFile {
    pub path: String,
    pub reason: Option<&'static str>,
}

/// What one backup cycle actually did, including transfer metrics — not
/// just file counts. `bytes_sent`/`duration_ms` come straight off the
/// connection's own QUIC stats (so they include protocol overhead, not
/// just ciphertext — a more honest "how long did this take" number than
/// summing file sizes), letting the dashboard show a real transfer rate
/// for the cycle instead of just "sent 3 files". Zeroed/None when the
/// cycle found nothing to do and never opened a connection at all.
#[derive(Debug, Clone, Default)]
pub struct BackupCycleStats {
    pub files_sent: usize,
    pub files_deleted: usize,
    pub bytes_sent: u64,
    pub duration_ms: u64,
    pub connection: Option<ConnectionQuality>,
    // bytes_sent split by the paths that actually carried it, for the
    // relay/direct totals (and relay billing). None when nothing connected.
    pub traffic: Option<netinfo::ByteSplit>,
    // How many put/delete calls failed this cycle — not fatal (the cycle
    // itself still ran, and anything that failed just stays in next
    // cycle's diff and gets retried), but worth the dashboard calling out:
    // a file that keeps failing every cycle isn't a transient blip.
    pub files_failed: usize,
    // A capped sample of which paths failed, with a reason when the buddy
    // gave us one — not every failure if there are many, just enough to
    // point someone at the problem.
    pub failed_paths: Vec<FailedFile>,
}

const MAX_FAILED_PATHS_SHOWN: usize = 10;

/// Live progress of one buddy's backup cycle while it runs, so a long first
/// backup shows signs of life on the dashboard instead of "no cycle yet"
/// for hours. Only present while a cycle is running; removed when it ends
/// (success or not), at which point the normal last-cycle record takes over.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CycleProgress {
    /// "checking" (looking for new/changed files, reading any that changed),
    /// "sending", or "deleting" (telling the buddy about deleted files).
    pub phase: &'static str,
    pub files_total: usize,
    pub files_checked: usize,
    pub files_to_send: usize,
    pub files_sent: usize,
    pub bytes_to_send: u64,
    /// Bytes of fully finished files; the current file's share is added
    /// from `current_done` when the dashboard reads it.
    pub bytes_sent: u64,
    pub files_to_delete: usize,
    pub files_deleted: usize,
    pub current_path: Option<String>,
    pub current_size: u64,
    /// Bytes read/sent of the current file so far (filled in by `snapshot`).
    pub current_done: u64,
    pub started_unix: u64,
    /// When the sending phase started — the transfer rate and time left are
    /// measured from here, not from the start of checking.
    pub sending_started_unix: Option<u64>,
    /// This device's clock when the snapshot was taken, so the browser
    /// measures elapsed time against the same clock (no skew).
    pub now_unix: u64,
    /// Bytes of resumed uploads the buddy already had: they move the bar
    /// but weren't sent this cycle, so the speed leaves them out (after a
    /// resume it read "144 MB/s, ~3s left").
    pub bytes_skipped: u64,
    #[serde(skip)]
    current_counter: Arc<AtomicU64>,
    #[serde(skip)]
    skipped_counter: Arc<AtomicU64>,
}

impl CycleProgress {
    /// A copy with `current_done`/`now_unix` filled in from the live counter.
    pub fn snapshot(&self) -> CycleProgress {
        let mut copy = self.clone();
        copy.current_done = self.current_counter.load(Ordering::Relaxed).min(self.current_size);
        copy.now_unix = crate::dashboard::unix_now();
        copy.bytes_skipped = self.skipped_counter.load(Ordering::Relaxed);
        copy
    }
}

/// In-flight cycle progress per buddy node id — shared with the dashboard.
pub type CycleProgressBook = Arc<Mutex<HashMap<String, CycleProgress>>>;

/// Updates one buddy's entry in a `CycleProgressBook`, and removes it when
/// dropped, so an early return or error never leaves a stuck progress bar.
struct ProgressTracker {
    book: Option<CycleProgressBook>,
    node_id: String,
    counter: Arc<AtomicU64>,
    skipped: Arc<AtomicU64>,
}

impl ProgressTracker {
    fn new(book: Option<&CycleProgressBook>, node_id: &str) -> Self {
        let counter = Arc::new(AtomicU64::new(0));
        let skipped = Arc::new(AtomicU64::new(0));
        if let Some(book) = book {
            book.lock().unwrap().insert(
                node_id.to_string(),
                CycleProgress {
                    phase: "checking",
                    started_unix: crate::dashboard::unix_now(),
                    current_counter: counter.clone(),
                    skipped_counter: skipped.clone(),
                    ..Default::default()
                },
            );
        }
        Self { book: book.cloned(), node_id: node_id.to_string(), counter, skipped }
    }

    fn update(&self, f: impl FnOnce(&mut CycleProgress)) {
        if let Some(book) = &self.book
            && let Some(p) = book.lock().unwrap().get_mut(&self.node_id)
        {
            f(p);
        }
    }

    /// Starts tracking a new current file (resets the byte counter).
    fn start_file(&self, path: &str, size: u64) {
        self.counter.store(0, Ordering::Relaxed);
        self.update(|p| {
            p.current_path = Some(path.to_string());
            p.current_size = size;
        });
    }

    fn clear_file(&self) {
        self.counter.store(0, Ordering::Relaxed);
        self.update(|p| {
            p.current_path = None;
            p.current_size = 0;
        });
    }
}

impl Drop for ProgressTracker {
    fn drop(&mut self) {
        if let Some(book) = &self.book {
            book.lock().unwrap().remove(&self.node_id);
        }
    }
}

/// Files a buddy has refused, and why, so each refusal is logged once
/// rather than every cycle. Keyed by (buddy, path); forgotten when the file
/// goes through, so a later refusal is logged again. In memory only: a
/// restart logs each refusal once more, which is a useful reminder.
static REFUSALS: std::sync::LazyLock<Mutex<HashMap<(String, String), &'static str>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Records a refusal; true if it's new (or the reason changed) and so
/// worth logging.
fn note_refusal(buddy: &str, path: &str, reason: &'static str) -> bool {
    REFUSALS.lock().unwrap().insert((buddy.to_string(), path.to_string()), reason) != Some(reason)
}

fn forget_refusal(buddy: &str, path: &str) {
    REFUSALS.lock().unwrap().remove(&(buddy.to_string(), path.to_string()));
}

/// Pulls a `PutRejectReason` out of an upload error, when the failure was
/// the buddy refusing the file: its STOP_SENDING code (walking the anyhow
/// error's source chain, since `write_all`'s `WriteError::Stopped` gets
/// wrapped in `.context(...)` on the way out), or a resumable upload's
/// up-front `Refused`.
fn reject_reason_from_err(err: &anyhow::Error) -> Option<&'static str> {
    err.chain()
        .find_map(|cause| {
            if let Some(Refused(reason)) = cause.downcast_ref::<Refused>() {
                return Some(*reason);
            }
            match cause.downcast_ref::<iroh::endpoint::WriteError>()? {
                iroh::endpoint::WriteError::Stopped(code) => PutRejectReason::from_code(code.into_inner()),
                _ => None,
            }
        })
        .map(PutRejectReason::message)
}

/// One pass: scan `backup_dir`, diff against what we last told `buddy_id`
/// we'd sent them, and push anything new, changed, or deleted. Connects to
/// the buddy only if there's actually something to send — most cycles,
/// after the first, should find nothing changed and do no network work at
/// all.
pub async fn run_backup_cycle(
    endpoint: &Endpoint,
    relay_url: &RelayUrl,
    backup_dir: &Path,
    buddy_id: EndpointId,
    progress: Option<&CycleProgressBook>,
) -> Result<BackupCycleStats> {
    let buddy_node_id = buddy_id.to_string();
    let tracker = ProgressTracker::new(progress, &buddy_node_id);
    let idx = index::get();
    let sent = idx.sent_entries(&buddy_node_id)?;

    let scan = scan_local_files(backup_dir).await?;
    let local_files = scan.files;
    tracker.update(|p| p.files_total = local_files.len());

    // A folder that suddenly looks completely empty while the buddy holds
    // files from it is far more likely to be a drive that isn't mounted (or
    // a broken mount) than someone deliberately deleting everything —
    // mirroring it would send a delete for every file. Stop and say so
    // instead; ALLOW_EMPTY_BACKUP_DIR=true overrides it for the real thing.
    if looks_like_missing_drive(local_files.len(), scan.unreadable.len(), sent.len())
        && !allow_empty_backup_dir()
    {
        if scan.excluded > 0 {
            anyhow::bail!(
                "your exclude list (excludes.txt in the config folder) leaves nothing in your backup folder to                  back up, but {} file(s) from it are backed up with this buddy — not deleting them all.                  Check it for a pattern that's broader than you meant, like `*` or `**`.",
                sent.len()
            );
        }
        anyhow::bail!(
            "your backup folder ({}) looks empty, but {} file(s) from it are backed up with this buddy — \
             not deleting them all. Is the drive with your files mounted? If you really did delete \
             everything, set ALLOW_EMPTY_BACKUP_DIR=true in .env and restart (then remove it again).",
            crate::host_dir_label(backup_dir, "BACKUP_DIR_HOST"),
            sent.len()
        );
    }

    // Problems on this side (files or folders we can't read) are reported
    // like any other failed file, but don't stop the rest of the cycle.
    let mut files_failed = 0usize;
    let mut failed_paths = Vec::new();
    for path in &scan.unreadable {
        files_failed += 1;
        if failed_paths.len() < MAX_FAILED_PATHS_SHOWN {
            failed_paths.push(FailedFile {
                path: if path.is_empty() { "(backup folder)".to_string() } else { path.clone() },
                reason: Some("can't open this on this device — check permissions; deletions paused until fixed"),
            });
        }
    }

    // Change detection: a file is only read (hashed) when its size or
    // modified time differs from what the index recorded last time. For an
    // unchanged folder a cycle is a metadata-only listing, however big the
    // files are.
    let mut to_put: Vec<(String, PathBuf, u64, String)> = Vec::new();
    for (checked, f) in local_files.iter().enumerate() {
        // Cheap per-file update (one lock, one field) — drives the
        // dashboard's "checked N of M" while a big folder is first read.
        tracker.update(|p| p.files_checked = checked);
        let sha256 = match idx.cached_hash(&f.rel_path, f.size, f.mtime_ns)? {
            Some(hash) => hash,
            None => {
                tracker.start_file(&f.rel_path, f.size);
                let hashed =
                    crate::crypto::sha256_file_counted(f.abs_path.clone(), Some(tracker.counter.clone())).await;
                match hashed {
                    Ok(hash) => {
                        idx.remember_hash(&f.rel_path, f.size, f.mtime_ns, &hash)?;
                        hash
                    }
                    Err(err) => {
                        // One unreadable file used to abort the whole cycle (so
                        // nothing else got backed up either). It stays in
                        // local_paths below, so it's never mistaken for deleted.
                        tracing::warn!(path = %f.rel_path, ?err, "can't read file — skipping it this cycle");
                        files_failed += 1;
                        if failed_paths.len() < MAX_FAILED_PATHS_SHOWN {
                            failed_paths.push(FailedFile {
                                path: f.rel_path.clone(),
                                reason: Some("can't read this file on this device — check its permissions"),
                            });
                        }
                        continue;
                    }
                }
            }
        };
        let changed = sent.get(&f.rel_path).is_none_or(|e| e.sha256 != sha256 || e.size != f.size);
        if changed {
            to_put.push((f.rel_path.clone(), f.abs_path.clone(), f.size, sha256));
        }
    }

    tracker.clear_file();
    tracker.update(|p| p.files_checked = local_files.len());

    let local_paths: HashSet<&String> = local_files.iter().map(|f| &f.rel_path).collect();
    if scan.unreadable.is_empty() {
        idx.prune_hashes(&local_paths)?;
    } else {
        tracing::warn!(
            unreadable = scan.unreadable.len(),
            "parts of the backup folder couldn't be read — not mirroring any deletions this cycle"
        );
    }
    let to_delete = deletions_to_mirror(sent.keys(), &local_paths, scan.unreadable.len());
    // Say why files the person didn't delete are leaving the buddy.
    let newly_excluded = to_delete.iter().filter(|p| scan.rules.is_excluded(p)).count();
    if newly_excluded > 0 {
        tracing::info!(
            buddy = %buddy_node_id,
            files = newly_excluded,
            "backed-up files are now excluded — removing them from this buddy (they keep a copy for 30 days)"
        );
    }

    // Nothing to send and nothing wrong locally: skip the connection (the
    // caller pings instead). With local failures, still connect, so the
    // dashboard's reachability/staleness stays based on a real connection.
    if to_put.is_empty() && to_delete.is_empty() && files_failed == 0 {
        return Ok(BackupCycleStats::default());
    }

    let cycle_started = std::time::Instant::now();
    let addr = EndpointAddr::new(buddy_id).with_relay_url(relay_url.clone());
    let conn = endpoint.connect(addr, protocol::ALPN).await.map_err(protocol::explain_connect_error)?;
    let meter = netinfo::PathMeter::start(&conn, netinfo::Direction::Sent);

    // Streaming uploads need the buddy on client 0.5.0+; older buddies get
    // the old whole-file upload (size-limited, see LEGACY_PUT_MAX_BYTES).
    // Resumable uploads of big files need 0.8.0+.
    let buddy_version =
        if to_put.is_empty() { protocol::PROTOCOL_VERSION } else { buddy_protocol_version(&conn).await };
    let streaming = buddy_version >= 2;
    let resumable = buddy_version >= 3;
    if !streaming {
        tracing::info!("buddy runs an older client — using the old upload format until they update");
    }

    tracker.update(|p| {
        p.phase = "sending";
        p.files_to_send = to_put.len();
        p.bytes_to_send = to_put.iter().map(|(_, _, size, _)| *size).sum();
        p.files_to_delete = to_delete.len();
        p.sending_started_unix = Some(crate::dashboard::unix_now());
    });

    let mut put_count = 0;
    for (rel_path, abs_path, size, sha256) in &to_put {
        tracker.start_file(rel_path, *size);
        if !streaming && *size > protocol::LEGACY_PUT_MAX_BYTES {
            files_failed += 1;
            if failed_paths.len() < MAX_FAILED_PATHS_SHOWN {
                failed_paths.push(FailedFile {
                    path: rel_path.clone(),
                    reason: Some("your buddy's client is out of date — files over 512 MB will send once they update"),
                });
            }
            tracker.update(|p| {
                p.files_sent += 1;
                p.bytes_to_send = p.bytes_to_send.saturating_sub(*size);
            });
            continue;
        }
        let result = if resumable && *size >= RESUMABLE_MIN_BYTES {
            put_one_file_resumable(
                &conn,
                &buddy_node_id,
                rel_path,
                abs_path,
                *size,
                sha256,
                Some(&tracker.counter),
                Some(&tracker.skipped),
            )
            .await
        } else if streaming {
            put_one_file(&conn, rel_path, abs_path, *size, Some(&tracker.counter)).await
        } else {
            put_one_file_legacy(&conn, rel_path, abs_path, *size).await
        };
        // A failed file still moves the file count on (failures are listed
        // separately), but its bytes come off the total instead of counting
        // as sent — a buddy refusing files instantly would otherwise show a
        // huge speed and a near-zero time left.
        let ok = result.is_ok();
        tracker.update(|p| {
            p.files_sent += 1;
            if ok {
                p.bytes_sent += *size;
            } else {
                p.bytes_to_send = p.bytes_to_send.saturating_sub(*size);
            }
        });
        match result {
            Ok(ciphertext_size) => {
                put_count += 1;
                forget_refusal(&buddy_node_id, rel_path);
                // Recorded per file as it lands (one row, not a rewrite of
                // everything), so a cycle interrupted partway only re-sends
                // the file that was in flight.
                if let Err(err) = idx.record_sent(
                    &buddy_node_id,
                    rel_path,
                    &SentEntry { size: *size, sha256: sha256.clone(), ciphertext_size },
                ) {
                    tracing::warn!(path = %rel_path, ?err, "backed up file but failed to record it — may be re-sent next cycle");
                }
                // Already on this buddy, so this was a change re-sending the
                // whole file — counted for the dashboard's re-send warning.
                if sent.contains_key(rel_path)
                    && let Err(err) = idx.record_resend(&buddy_node_id, rel_path, *size)
                {
                    tracing::debug!(path = %rel_path, ?err, "couldn't record a re-send");
                }
            }
            Err(err) => {
                let reason = reject_reason_from_err(&err);
                match reason {
                    // The buddy refused it (pledge full, too large, …): the
                    // same answer comes back every cycle until something
                    // changes, so say it once rather than every 30s.
                    Some(reason) => {
                        if note_refusal(&buddy_node_id, rel_path, reason) {
                            tracing::warn!(path = %rel_path, reason, "buddy refused this file — will keep retrying quietly");
                        } else {
                            tracing::debug!(path = %rel_path, reason, "buddy refused this file again");
                        }
                    }
                    None => tracing::warn!(path = %rel_path, ?err, "failed to back up file — will retry next cycle"),
                }
                files_failed += 1;
                if failed_paths.len() < MAX_FAILED_PATHS_SHOWN {
                    failed_paths.push(FailedFile { path: rel_path.clone(), reason });
                }
            }
        }
    }

    tracker.clear_file();
    tracker.update(|p| p.phase = "deleting");
    let mut delete_count = 0;
    for rel_path in &to_delete {
        let result = delete_one_file(&conn, rel_path).await;
        tracker.update(|p| p.files_deleted += 1);
        match result {
            Ok(()) => {
                delete_count += 1;
                if let Err(err) = idx.forget_sent(&buddy_node_id, std::slice::from_ref(rel_path)) {
                    tracing::warn!(path = %rel_path, ?err, "told buddy about a deleted file but failed to record it — may retry next cycle");
                }
            }
            Err(err) => {
                tracing::warn!(path = %rel_path, ?err, "failed to tell buddy about a deleted file — will retry next cycle");
                files_failed += 1;
                if failed_paths.len() < MAX_FAILED_PATHS_SHOWN {
                    failed_paths.push(FailedFile { path: rel_path.clone(), reason: None });
                }
            }
        }
    }


    // Read straight off the connection's own QUIC stats rather than
    // summing what we think we sent — covers protocol overhead (framing,
    // acks, retransmits) too, which is what actually took the time.
    let stats = BackupCycleStats {
        files_sent: put_count,
        files_deleted: delete_count,
        bytes_sent: conn.stats().udp_tx.bytes,
        duration_ms: cycle_started.elapsed().as_millis() as u64,
        connection: Some(netinfo::connection_quality(&conn)),
        traffic: Some(meter.finish(&conn)),
        files_failed,
        failed_paths,
    };
    Ok(stats)
}

/// Result of comparing our manifest against what the buddy actually
/// reports holding for us — see `reconcile_with_buddy` below.
#[derive(Debug, Clone, Default)]
pub struct ReconcileStats {
    /// How many manifest entries were checked against the buddy's list.
    pub checked: usize,
    /// Paths our manifest believes landed, but the buddy either doesn't
    /// have (at all, or only as a `.versions/` backup slot — see
    /// `ListEntry::deleted`) or has at a different size. Already dropped
    /// from the manifest by the time this is returned, so the very next
    /// ordinary cycle re-sends them automatically — no separate re-send
    /// logic needed here.
    pub missing_on_buddy: Vec<String>,
    /// Paths the buddy has (live, not a `.versions/`-only slot) that our
    /// manifest has no record of sending. Reported only, never acted on
    /// automatically — deleting these from the buddy based on a guess
    /// would be destructive if the guess is wrong (e.g. a manifest this
    /// process just hasn't caught up on yet), so this is purely a loud
    /// surface for a person to look into.
    pub unexpected_on_buddy: Vec<String>,
}

/// Checks that the buddy's own actual stored files still match what our
/// manifest believes we sent them — unlike `run_backup_cycle` above,
/// which only ever diffs *local* files against the manifest (what we
/// believe we already sent), this catches drift that happens entirely
/// outside the normal put/delete flow: manual filesystem surgery on the
/// receiver, a bug, partial data loss on their end, restoring from an
/// old snapshot. None of those change anything about our local source
/// files, so an ordinary cycle has no way to ever notice them on its
/// own — this is what does. Meant to be called periodically rather than
/// every cycle (see main.rs's reconcile interval) since it costs the
/// buddy a full `List` of everything they're holding for us, heavier
/// than the ordinary diff-driven cycle which only touches the network
/// when something local actually changed.
pub async fn reconcile_with_buddy(
    endpoint: &Endpoint,
    relay_url: &RelayUrl,
    buddy_id: EndpointId,
) -> Result<ReconcileStats> {
    let buddy_node_id = buddy_id.to_string();
    let idx = index::get();
    let sent = idx.sent_entries(&buddy_node_id)?;
    if sent.is_empty() {
        // Nothing we believe we've sent this buddy, so nothing to check
        // — and no reason to open a connection just to confirm that.
        return Ok(ReconcileStats::default());
    }

    let buddy_files = crate::restore::list_buddy_files(endpoint, relay_url, buddy_id)
        .await
        .context("failed to list buddy's files for reconciliation")?;

    // Only live files count as "the buddy still has this" — a
    // `deleted: true` entry is a `.versions/` backup slot from something
    // that was overwritten or deleted, not the live file we're tracking
    // (see ListEntry's doc comment in protocol.rs).
    let buddy_live: HashMap<&str, u64> =
        buddy_files.iter().filter(|f| !f.deleted).map(|f| (f.path.as_str(), f.size)).collect();

    let checked = sent.len();
    let missing_on_buddy: Vec<String> = sent
        .iter()
        .filter(|(path, entry)| {
            !buddy_live.get(path.as_str()).is_some_and(|&size| size == entry.ciphertext_size)
        })
        .map(|(path, _)| path.clone())
        .collect();
    // Dropping them from the index makes the very next ordinary cycle see
    // those local files as changed and re-send them.
    if !missing_on_buddy.is_empty() {
        idx.forget_sent(&buddy_node_id, &missing_on_buddy)
            .context("failed to record reconciliation result")?;
    }

    let unexpected_on_buddy: Vec<String> = buddy_live
        .keys()
        .filter(|path| !sent.contains_key(**path))
        .map(|path| path.to_string())
        .collect();

    Ok(ReconcileStats { checked, missing_on_buddy, unexpected_on_buddy })
}

// ---- Resumable uploads (protocol v3) ---------------------------------------
//
// age encrypts every file with a fresh random key, so re-encrypting a file
// after a dropped connection gives different bytes, and the buddy's partial
// copy would be useless. For big files the sender therefore keeps the exact
// ciphertext it's sending in DATA_DIR/outgoing/ (encrypted, like everything
// that leaves this machine): a cut-off upload continues from that copy on
// the next cycle, sending only what the buddy doesn't have yet. The copy is
// deleted once the buddy confirms the file.

/// Files at least this big are sent resumably. Below it, a restart from
/// zero is cheap and writing a local copy first isn't worth it.
#[cfg(not(test))]
const RESUMABLE_MIN_BYTES: u64 = 256 * 1024 * 1024;
#[cfg(test)]
const RESUMABLE_MIN_BYTES: u64 = 1024 * 1024;

/// Free space to leave on DATA_DIR's disk beyond the copy itself; without
/// it, a file is sent the old way (no resume) rather than filling the disk.
const SPOOL_FREE_RESERVE_BYTES: u64 = 1024 * 1024 * 1024;

/// A copy nobody resumed for this long (the file was deleted, or the buddy
/// was unpaired) is cleared at startup.
const SPOOL_KEEP_DAYS: u64 = 7;

static SPOOL_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Test hooks: cut a first-attempt upload once this many bytes are sent
/// (0 = off), and record where the last resume started.
#[cfg(test)]
pub(crate) static TEST_CUT_AFTER_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
pub(crate) static TEST_LAST_RESUME_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Sets up DATA_DIR/outgoing/ for resumable uploads, clearing stale copies.
/// Without this (or if it fails), every file is sent the old way.
pub async fn init_spool(data_dir: &Path) {
    let dir = data_dir.join("outgoing");
    if let Err(err) = tokio::fs::create_dir_all(&dir).await {
        tracing::warn!(?err, "can't create DATA_DIR/outgoing — big files won't resume after an interruption");
        return;
    }
    crate::receive::remove_older_than(&dir, SPOOL_KEEP_DAYS).await;
    let _ = SPOOL_DIR.set(dir);
}

/// What a copy in DATA_DIR/outgoing/ holds. `ciphertext_sha256` is set
/// once the copy is complete; only then can it be resumed from.
#[derive(Serialize, serde::Deserialize)]
struct SpoolMeta {
    path: String,
    plaintext_sha256: String,
    plaintext_len: u64,
    upload_id: String,
    ciphertext_len: u64,
    ciphertext_sha256: Option<String>,
}

/// A buddy refused an upload before any bytes were sent (the resumable
/// handshake answers first), carrying the same reasons as STOP_SENDING.
#[derive(Debug)]
struct Refused(PutRejectReason);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0.message())
    }
}

impl std::error::Error for Refused {}

fn spool_paths(dir: &Path, buddy: &str, rel_path: &str) -> (PathBuf, PathBuf) {
    let key = &hex::encode(Sha256::digest(format!("{buddy}\n{rel_path}").as_bytes()))[..32];
    (dir.join(format!("{key}.ct")), dir.join(format!("{key}.json")))
}

async fn remove_spool(ct: &Path, meta: &Path) {
    let _ = tokio::fs::remove_file(ct).await;
    let _ = tokio::fs::remove_file(meta).await;
}

/// Unique per encryption; not secret, just never reused.
fn new_upload_id(rel_path: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let seed = format!("{rel_path}\n{}\n{nanos}\n{n}", std::process::id());
    hex::encode(Sha256::digest(seed.as_bytes()))[..32].to_string()
}

async fn spool_has_room(dir: &Path, bytes: u64) -> bool {
    let dir = dir.to_path_buf();
    match tokio::task::spawn_blocking(move || fs4::statvfs(&dir)).await {
        Ok(Ok(stats)) => stats.available_space() >= bytes.saturating_add(SPOOL_FREE_RESERVE_BYTES),
        _ => false,
    }
}

/// Sends a PutResumable header and returns how many bytes the buddy
/// already has. A refusal comes back as `Refused`.
async fn start_resumable(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    rel_path: &str,
    upload_id: &str,
    ciphertext_len: u64,
) -> Result<u64> {
    protocol::write_frame(
        send,
        &SyncRequest::PutResumable { path: rel_path.to_string(), upload_id: upload_id.to_string(), ciphertext_len },
    )
    .await?;
    let reply: protocol::PutResumeReply =
        protocol::read_frame(recv).await.context("failed to read buddy's reply to the upload")?;
    if let Some(offset) = reply.offset
        && offset <= ciphertext_len
    {
        return Ok(offset);
    }
    if let Some(reason) = reply.reject_code.and_then(PutRejectReason::from_code) {
        return Err(Refused(reason).into());
    }
    anyhow::bail!("buddy refused the upload: {}", reply.error.unwrap_or_default())
}

/// Trailer, end of stream, buddy's ack.
async fn finish_put(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    ciphertext_sha256: String,
) -> Result<()> {
    protocol::write_frame(send, &protocol::PutTrailer { ciphertext_sha256 }).await?;
    send.finish().context("failed to finish send stream")?;
    let ack: SyncAck = protocol::read_frame(recv).await.context("failed to read ack")?;
    if !ack.ok {
        anyhow::bail!("buddy rejected file: {}", ack.error.unwrap_or_default());
    }
    Ok(())
}

/// Uploads one big file so that an interruption can be resumed (protocol
/// v3), falling back to an ordinary upload when there's no room for the
/// local copy. Returns the encrypted size, like put_one_file.
#[allow(clippy::too_many_arguments)]
async fn put_one_file_resumable(
    conn: &iroh::endpoint::Connection,
    buddy: &str,
    rel_path: &str,
    abs_path: &Path,
    plaintext_len: u64,
    plaintext_sha256: &str,
    bytes_sent: Option<&Arc<AtomicU64>>,
    bytes_skipped: Option<&Arc<AtomicU64>>,
) -> Result<u64> {
    let Some(dir) = SPOOL_DIR.get() else {
        return put_one_file(conn, rel_path, abs_path, plaintext_len, bytes_sent).await;
    };
    let (ct_path, meta_path) = spool_paths(dir, buddy, rel_path);

    // A finished copy of exactly this content: carry on from it.
    let existing = tokio::fs::read(&meta_path).await.ok().and_then(|b| serde_json::from_slice::<SpoolMeta>(&b).ok());
    if let Some(meta) = existing {
        let ct_len = tokio::fs::metadata(&ct_path).await.map(|m| m.len()).ok();
        if meta.path == rel_path
            && meta.plaintext_sha256 == plaintext_sha256
            && meta.plaintext_len == plaintext_len
            && meta.ciphertext_sha256.is_some()
            && ct_len == Some(meta.ciphertext_len)
        {
            let result = send_from_spool(conn, &meta, &ct_path, bytes_sent, bytes_skipped).await;
            if result.is_ok() || drop_spool_after(result.as_ref().err()) {
                remove_spool(&ct_path, &meta_path).await;
            }
            return result.map(|_| meta.ciphertext_len);
        }
    }
    remove_spool(&ct_path, &meta_path).await;

    if !spool_has_room(dir, plaintext_len).await {
        tracing::info!(path = %rel_path, "not enough free space in DATA_DIR for a resumable copy — sending without one");
        return put_one_file(conn, rel_path, abs_path, plaintext_len, bytes_sent).await;
    }
    let result = spool_and_send(conn, rel_path, abs_path, plaintext_len, plaintext_sha256, &ct_path, &meta_path, bytes_sent).await;
    if result.is_ok() || drop_spool_after(result.as_ref().err()) {
        remove_spool(&ct_path, &meta_path).await;
    }
    result
}

/// Whether a failed upload's local copy is worth keeping: yes after a
/// dropped connection (that's what it's for), no when the buddy refused
/// the file or the bytes didn't check out.
fn drop_spool_after(err: Option<&anyhow::Error>) -> bool {
    let Some(err) = err else { return false };
    reject_reason_from_err(err).is_some() || format!("{err:#}").contains("hash mismatch")
}

/// Resumes from a complete local copy: asks the buddy how much it has and
/// sends the rest.
async fn send_from_spool(
    conn: &iroh::endpoint::Connection,
    meta: &SpoolMeta,
    ct_path: &Path,
    bytes_sent: Option<&Arc<AtomicU64>>,
    bytes_skipped: Option<&Arc<AtomicU64>>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;
    let offset = start_resumable(&mut send, &mut recv, &meta.path, &meta.upload_id, meta.ciphertext_len).await?;
    if offset > 0 {
        tracing::info!(path = %meta.path, offset, total = meta.ciphertext_len, "resuming upload");
    }
    #[cfg(test)]
    TEST_LAST_RESUME_OFFSET.store(offset, Ordering::Relaxed);
    // The bytes the buddy already holds count as done on the progress bar.
    if let Some(counter) = bytes_sent {
        counter.fetch_add(offset, Ordering::Relaxed);
    }
    if let Some(skipped) = bytes_skipped {
        skipped.fetch_add(offset, Ordering::Relaxed);
    }
    let mut file = tokio::fs::File::open(ct_path).await.context("failed to open the resumable copy")?;
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    let mut buf = vec![0u8; crate::crypto::PIPE_CHUNK];
    let mut left = meta.ciphertext_len - offset;
    while left > 0 {
        let want = left.min(buf.len() as u64) as usize;
        let n = file.read(&mut buf[..want]).await?;
        if n == 0 {
            anyhow::bail!("the resumable copy is shorter than recorded");
        }
        send.write_all(&buf[..n]).await.context("failed to send file bytes")?;
        if let Some(counter) = bytes_sent {
            counter.fetch_add(n as u64, Ordering::Relaxed);
        }
        left -= n as u64;
    }
    let hash = meta.ciphertext_sha256.clone().unwrap_or_default();
    finish_put(&mut send, &mut recv, hash).await
}

/// First attempt: encrypts once, writing every byte to the local copy and
/// to the buddy. If the connection drops partway, encryption carries on
/// into the copy, so the next cycle can resume from it.
#[allow(clippy::too_many_arguments)]
async fn spool_and_send(
    conn: &iroh::endpoint::Connection,
    rel_path: &str,
    abs_path: &Path,
    plaintext_len: u64,
    plaintext_sha256: &str,
    ct_path: &Path,
    meta_path: &Path,
    bytes_sent: Option<&Arc<AtomicU64>>,
) -> Result<u64> {
    use tokio::io::AsyncWriteExt;
    let mut enc = crate::crypto::encrypt_file(abs_path.to_path_buf(), plaintext_len);
    let ciphertext_len = match (&mut enc.ciphertext_len).await {
        Ok(len) => len,
        Err(_) => {
            return Err(enc.done.await.context("encryption task failed")?.err().unwrap_or_else(|| {
                anyhow::anyhow!("encryption stopped unexpectedly")
            }));
        }
    };

    let upload_id = new_upload_id(rel_path);
    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;
    // Refused (pledge full…) before a byte is encrypted to disk.
    let offset = start_resumable(&mut send, &mut recv, rel_path, &upload_id, ciphertext_len).await?;

    let mut meta = SpoolMeta {
        path: rel_path.to_string(),
        plaintext_sha256: plaintext_sha256.to_string(),
        plaintext_len,
        upload_id,
        ciphertext_len,
        ciphertext_sha256: None,
    };
    tokio::fs::write(meta_path, serde_json::to_vec(&meta)?).await.context("failed to write the resumable copy")?;
    let mut spool = tokio::fs::File::create(ct_path).await.context("failed to create the resumable copy")?;

    let mut hasher = Sha256::new();
    let mut written = 0u64;
    let mut network_err: Option<anyhow::Error> = None;
    while let Some(chunk) = enc.chunks.recv().await {
        spool.write_all(&chunk).await.context("failed to write the resumable copy")?;
        hasher.update(&chunk);
        let start = written;
        written += chunk.len() as u64;
        if network_err.is_none() && written > offset {
            let skip = offset.saturating_sub(start) as usize;
            match send.write_all(&chunk[skip..]).await {
                Ok(()) => {
                    if let Some(counter) = bytes_sent {
                        counter.fetch_add((chunk.len() - skip) as u64, Ordering::Relaxed);
                    }
                    #[cfg(test)]
                    {
                        let cut = TEST_CUT_AFTER_BYTES.load(Ordering::Relaxed);
                        if cut > 0 && written >= cut {
                            send.reset(iroh::endpoint::VarInt::from_u32(0)).ok();
                            network_err = Some(anyhow::anyhow!("simulated connection drop"));
                        }
                    }
                }
                Err(err) => {
                    let err = anyhow::Error::from(err).context("failed to send file bytes");
                    // Refused partway (e.g. the buddy's disk filled up):
                    // nothing to resume.
                    if reject_reason_from_err(&err).is_some() {
                        return Err(err);
                    }
                    tracing::info!(path = %rel_path, sent = start, total = ciphertext_len, "connection dropped mid-file — finishing the local copy so it can resume next cycle");
                    network_err = Some(err);
                }
            }
        }
    }
    enc.done.await.context("encryption task failed")??;
    spool.sync_all().await.context("failed to flush the resumable copy")?;
    if written != ciphertext_len {
        anyhow::bail!("encrypted {written} bytes but announced {ciphertext_len} — aborting this file");
    }
    let hash = hex::encode(hasher.finalize());
    meta.ciphertext_sha256 = Some(hash.clone());
    tokio::fs::write(meta_path, serde_json::to_vec(&meta)?).await.context("failed to write the resumable copy")?;

    if let Some(err) = network_err {
        return Err(err);
    }
    finish_put(&mut send, &mut recv, hash).await?;
    Ok(ciphertext_len)
}

/// Encrypts and uploads one file as a stream (protocol v2 PutStream), in
/// bounded memory whatever its size. Returns the encrypted size stored on
/// the buddy's side, which the index records for the dashboard and for
/// reconciliation.
async fn put_one_file(
    conn: &iroh::endpoint::Connection,
    rel_path: &str,
    abs_path: &Path,
    plaintext_len: u64,
    bytes_sent: Option<&Arc<AtomicU64>>,
) -> Result<u64> {
    let mut enc = crate::crypto::encrypt_file(abs_path.to_path_buf(), plaintext_len);
    let ciphertext_len = match (&mut enc.ciphertext_len).await {
        Ok(len) => len,
        // Encryption ended before it could start (e.g. the file can't be
        // opened) — report why.
        Err(_) => {
            return Err(enc.done.await.context("encryption task failed")?.err().unwrap_or_else(|| {
                anyhow::anyhow!("encryption stopped unexpectedly")
            }));
        }
    };

    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;
    protocol::write_frame(
        &mut send,
        &SyncRequest::PutStream { path: rel_path.to_string(), ciphertext_len },
    )
    .await?;

    let mut hasher = Sha256::new();
    let mut sent = 0u64;
    while let Some(chunk) = enc.chunks.recv().await {
        hasher.update(&chunk);
        sent += chunk.len() as u64;
        // A rejection by the buddy (pledge full, disk full…) arrives as
        // STOP_SENDING and fails this write — see reject_reason_from_err.
        send.write_all(&chunk).await.context("failed to send file bytes")?;
        if let Some(counter) = bytes_sent {
            counter.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        }
    }
    enc.done.await.context("encryption task failed")??;
    if sent != ciphertext_len {
        anyhow::bail!("sent {sent} bytes but announced {ciphertext_len} — aborting this file");
    }
    protocol::write_frame(
        &mut send,
        &protocol::PutTrailer { ciphertext_sha256: hex::encode(hasher.finalize()) },
    )
    .await?;
    send.finish().context("failed to finish send stream")?;

    let ack: SyncAck = protocol::read_frame(&mut recv).await.context("failed to read ack")?;
    if !ack.ok {
        anyhow::bail!("buddy rejected file: {}", ack.error.unwrap_or_default());
    }
    Ok(ciphertext_len)
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

/// The pre-0.5.0 upload, for buddies that haven't updated: the hash goes
/// in the header, so the encrypted file is assembled in memory first.
/// Callers keep this to files under LEGACY_PUT_MAX_BYTES.
async fn put_one_file_legacy(
    conn: &iroh::endpoint::Connection,
    rel_path: &str,
    abs_path: &Path,
    plaintext_len: u64,
) -> Result<u64> {
    let mut enc = crate::crypto::encrypt_file(abs_path.to_path_buf(), plaintext_len);
    let mut ciphertext = Vec::new();
    while let Some(chunk) = enc.chunks.recv().await {
        ciphertext.extend_from_slice(&chunk);
    }
    enc.done.await.context("encryption task failed")??;
    let ciphertext_len = ciphertext.len() as u64;

    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;
    protocol::write_frame(
        &mut send,
        &SyncRequest::Put {
            path: rel_path.to_string(),
            ciphertext_len,
            ciphertext_sha256: hex::encode(Sha256::digest(&ciphertext)),
        },
    )
    .await?;
    send.write_all(&ciphertext).await.context("failed to send file bytes")?;
    send.finish().context("failed to finish send stream")?;

    let ack: SyncAck = protocol::read_frame(&mut recv).await.context("failed to read ack")?;
    if !ack.ok {
        anyhow::bail!("buddy rejected file: {}", ack.error.unwrap_or_default());
    }
    Ok(ciphertext_len)
}

async fn delete_one_file(conn: &iroh::endpoint::Connection, rel_path: &str) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;
    protocol::write_frame(&mut send, &SyncRequest::Delete { path: rel_path.to_string() }).await?;
    send.finish().context("failed to finish send stream")?;

    let ack: SyncAck = protocol::read_frame(&mut recv).await.context("failed to read ack")?;
    if !ack.ok {
        anyhow::bail!("buddy rejected delete: {}", ack.error.unwrap_or_default());
    }
    Ok(())
}

/// File count, total (plaintext) bytes and excluded count (files plus
/// skipped folders) under `backup_dir` right now —
/// for the dashboard's "This Device" panel, not the sync protocol. A
/// plain re-scan rather than anything manifest-based, since this is meant
/// to show what's actually sitting in the directory, independent of
/// whether it's been backed up to any particular buddy yet.
pub async fn local_backup_summary(backup_dir: &Path) -> Result<(usize, u64, usize)> {
    let scan = scan_local_files(backup_dir).await?;
    let total_bytes = scan.files.iter().map(|f| f.size).sum();
    Ok((scan.files.len(), total_bytes, scan.excluded))
}

/// One file found in BACKUP_DIR. `mtime_ns` is its modified time in
/// nanoseconds since the epoch (-1 if unavailable, which never matches a
/// cached entry, so the file is simply re-hashed).
struct LocalFile {
    rel_path: String,
    abs_path: PathBuf,
    size: u64,
    mtime_ns: i64,
}

/// What a scan of BACKUP_DIR found: the files it could see, plus anything
/// it couldn't open (relative paths). Unreadable entries matter: a folder
/// the client isn't allowed to open looks exactly like a folder that was
/// deleted, so callers must not treat "not in `files`" as "gone" while
/// `unreadable` is non-empty. Excluded files are left out of `files`, so
/// one that was backed up before is mirrored as deleted.
struct LocalScan {
    files: Vec<LocalFile>,
    unreadable: Vec<String>,
    /// Files and skipped folders the exclude list kept out.
    excluded: usize,
    rules: crate::excludes::Rules,
}

fn rel_to(backup_dir: &Path, abs_path: &Path) -> String {
    abs_path
        .strip_prefix(backup_dir)
        .unwrap_or(abs_path)
        .to_string_lossy()
        .replace('\\', "/") // normalize separators in case this ever runs on Windows
}

// Metadata only — no file contents are read here. Runs on a blocking
// thread, since walking a large folder can take a while. The exclude list
// is re-read each time, so edits apply on the next cycle.
async fn scan_local_files(backup_dir: &Path) -> Result<LocalScan> {
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
        let abs_path = entry.path().to_path_buf();
        let rel_path = rel_to(backup_dir, &abs_path);
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
        out.push(LocalFile { rel_path, abs_path, size, mtime_ns });
    }
    LocalScan { files: out, unreadable, excluded: excluded.get(), rules }
}

/// True when BACKUP_DIR scanned completely (nothing unreadable) yet came
/// back empty while the buddy holds files from it — the signature of a
/// drive that isn't mounted rather than a real "delete everything".
fn looks_like_missing_drive(local_files: usize, unreadable: usize, backed_up: usize) -> bool {
    local_files == 0 && unreadable == 0 && backed_up > 0
}

/// Which backed-up paths to delete from the buddy. Anything under a folder
/// we couldn't open is missing from `local_paths` without having been
/// deleted, so there are no deletions at all while any part of the scan
/// failed — new and changed files still go out.
fn deletions_to_mirror<'a>(
    backed_up: impl Iterator<Item = &'a String>,
    local_paths: &HashSet<&String>,
    unreadable: usize,
) -> Vec<String> {
    if unreadable > 0 {
        return Vec::new();
    }
    backed_up.filter(|rel| !local_paths.contains(rel)).cloned().collect()
}

/// ALLOW_EMPTY_BACKUP_DIR=true lets a cycle mirror "everything was deleted"
/// to the buddy. Off by default — see the empty-folder guard in
/// run_backup_cycle.
pub fn allow_empty_backup_dir() -> bool {
    matches!(
        std::env::var("ALLOW_EMPTY_BACKUP_DIR").map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Ok("1" | "true" | "yes")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_refusal_is_logged_once_until_it_changes() {
        let (buddy, path) = ("refusal-test-buddy", "a/b.jpg");
        assert!(note_refusal(buddy, path, "full"));
        assert!(!note_refusal(buddy, path, "full"));
        assert!(note_refusal(buddy, path, "too big"));
        forget_refusal(buddy, path);
        assert!(note_refusal(buddy, path, "too big"));
    }

    fn tmp(name: &str) -> PathBuf {
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
    fn deletions_pause_while_anything_is_unreadable() {
        let backed_up = ["a.txt".to_string(), "photos/b.jpg".to_string()];
        let present = "a.txt".to_string();
        let local: HashSet<&String> = [&present].into_iter().collect();
        assert_eq!(deletions_to_mirror(backed_up.iter(), &local, 0), vec!["photos/b.jpg".to_string()]);
        assert!(deletions_to_mirror(backed_up.iter(), &local, 1).is_empty());
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
