// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bandwidth::BandwidthBook;
use crate::netinfo::{self, ConnectionQuality};
use crate::protocol::{
    self, DiskStatsResponse, ListEntry, ListResponse, ListVersionsResponse, PutRejectReason,
    SyncAck, SyncRequest, VersionEntry,
};

// Never let incoming buddy data consume the disk down to nothing, no
// matter what's been pledged — pledges are numbers two people agreed on
// over the API, not a reservation the OS enforces, and an over-pledge (or
// just something else on the same disk growing) shouldn't be able to take
// this host down. The floor is whichever is bigger: a flat 2GB, or 5% of
// the filesystem's total size, so it scales sensibly from a small test
// box up to a many-terabyte server.
const MIN_FREE_RESERVE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MIN_FREE_RESERVE_PERCENT: u64 = 5;

// Real, physical headroom check — independent of and in addition to the
// per-buddy pledge enforcement in handle_put below. Fails open (allows
// the write) if disk stats can't be read at all, since a transient statvfs
// error shouldn't block every incoming backup; the pledge check is still
// the primary guard in that case.
//
// Measured on the filesystem holding BUDDY_FILES_DIR — where incoming data
// actually lands — not DATA_DIR, since the two can be different disks.
async fn disk_has_room_for(buddy_files_dir: &Path, additional_bytes: u64) -> bool {
    let buddy_files_dir = buddy_files_dir.to_path_buf();
    match tokio::task::spawn_blocking(move || fs4::statvfs(&buddy_files_dir)).await {
        Ok(Ok(stats)) => {
            let reserve = MIN_FREE_RESERVE_BYTES.max(stats.total_space() / 100 * MIN_FREE_RESERVE_PERCENT);
            let usable = stats.available_space().saturating_sub(reserve);
            additional_bytes <= usable
        }
        _ => true,
    }
}

// How many *previous* copies of a file are kept once it's overwritten or
// deleted, on top of the live one — 2 backups + the live copy = 3 versions
// total recoverable at any time. A pledge or the real-disk floor above
// still bounds how much space any of this can consume; this just bounds
// the multiplier a single churning file can add on top of its live size,
// so "someone keeps editing one huge file" can't quietly balloon disk use
// without limit.
const MAX_BACKUP_VERSIONS: u32 = 2;

fn versions_root(sender_dir: &Path) -> PathBuf {
    sender_dir.join(".versions")
}

fn version_path(sender_dir: &Path, rel_path: &str, slot: u32) -> Option<PathBuf> {
    safe_join(&versions_root(sender_dir), &format!("{rel_path}.v{slot}"))
}

// Called just before a path's live content is about to be replaced
// (overwrite) or removed (delete). Shifts existing backup slots down by
// one (dropping the oldest once MAX_BACKUP_VERSIONS is reached), then
// moves the *current* live file into the newest slot — so a delete isn't
// destructive (the deleted content becomes a recoverable backup) and an
// overwrite doesn't lose what was there before. A no-op if there's no
// live file yet (first write for this path — nothing to protect).
async fn rotate_versions(sender_dir: &Path, rel_path: &str) {
    let Some(live) = safe_join(sender_dir, rel_path) else { return };
    if tokio::fs::metadata(&live).await.is_err() {
        return;
    }

    if let Some(oldest) = version_path(sender_dir, rel_path, MAX_BACKUP_VERSIONS) {
        let _ = tokio::fs::remove_file(&oldest).await;
    }
    for slot in (1..MAX_BACKUP_VERSIONS).rev() {
        let (Some(from), Some(to)) =
            (version_path(sender_dir, rel_path, slot), version_path(sender_dir, rel_path, slot + 1))
        else {
            continue;
        };
        if tokio::fs::metadata(&from).await.is_ok() {
            if let Some(parent) = to.parent() {
                let _ = tokio::fs::create_dir_all(parent).await;
            }
            let _ = tokio::fs::rename(&from, &to).await;
        }
    }
    // A .versions/ created now can only ever hold copies dated "when
    // kept", so it gets the retention marker straight away; otherwise the
    // first daily sweep would treat its copies as pre-retention and
    // re-date them (pushing their removal back by up to a day).
    let versions = versions_root(sender_dir);
    if tokio::fs::metadata(&versions).await.is_err()
        && tokio::fs::create_dir_all(&versions).await.is_ok()
    {
        let _ = tokio::fs::write(versions.join(RETENTION_MARKER), RETENTION_MARKER_TEXT).await;
    }
    if let Some(slot1) = version_path(sender_dir, rel_path, 1) {
        if let Some(parent) = slot1.parent()
            && let Err(err) = tokio::fs::create_dir_all(parent).await
        {
            tracing::warn!(path = %rel_path, ?err, "couldn't create version directory — not keeping a backup of this overwrite");
            return;
        }
        if let Err(err) = tokio::fs::rename(&live, &slot1).await {
            tracing::warn!(path = %rel_path, ?err, "couldn't rotate previous version into a backup slot");
            return;
        }
        stamp_kept_now(&slot1).await;
    }
}

/// Backup copies (content a buddy replaced or deleted) are kept this long
/// after they became copies, then removed for good. Pledges only count live
/// files, so without a limit a buddy who backs up 100 GB, deletes it and
/// backs up another 100 GB would leave 200 GB on this disk against a 100 GB
/// pledge, growing for as long as the pairing lasts.
pub const VERSION_RETENTION_DAYS: u64 = 30;

/// Marks a sender's `.versions/` as dated by "when kept" (see
/// expire_versions); its absence means copies still carry their upload
/// time from before retention existed.
const RETENTION_MARKER: &str = ".retention-v1";
const RETENTION_MARKER_TEXT: &[u8] = b"backup copies here are dated by when they were kept\n";

fn retention() -> std::time::Duration {
    std::time::Duration::from_secs(VERSION_RETENTION_DAYS * 24 * 60 * 60)
}

/// Stamps a just-made backup copy with the current time: a rename keeps
/// the file's original (upload) time, but retention and the dashboard's
/// "kept … ago" count from when it became a copy.
async fn stamp_kept_now(path: &Path) {
    let path = path.to_path_buf();
    let _ = tokio::task::spawn_blocking(move || {
        std::fs::File::options().write(true).open(&path).and_then(|f| f.set_modified(std::time::SystemTime::now()))
    })
    .await;
}

/// When a backup copy will be removed, for the dashboard's History.
fn expires_unix(kept: std::time::SystemTime) -> Option<u64> {
    (kept + retention()).duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs())
}

/// Removes backup copies older than VERSION_RETENTION_DAYS from every
/// sender's `.versions/`, and the folders that leaves empty. Returns how
/// many files and bytes went. Run at startup and daily (main.rs).
///
/// Copies made before retention existed are dated by their upload time,
/// not when they were kept, so the first run for a sender only re-dates
/// them to now (and writes RETENTION_MARKER): a file deleted yesterday but
/// uploaded months ago must not disappear the moment this ships.
pub async fn expire_versions(buddy_files_dir: &Path) -> (usize, u64) {
    let root = buddy_files_dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut removed = (0usize, 0u64);
        let Ok(senders) = std::fs::read_dir(&root) else { return removed };
        let now = std::time::SystemTime::now();
        for sender in senders.flatten() {
            let versions = sender.path().join(".versions");
            if !versions.is_dir() {
                continue;
            }
            let marker = versions.join(RETENTION_MARKER);
            let first_run = !marker.exists();
            for entry in walkdir::WalkDir::new(&versions).contents_first(true).into_iter().flatten() {
                let path = entry.path();
                if entry.file_type().is_dir() {
                    if path != versions {
                        // Only succeeds when empty.
                        let _ = std::fs::remove_dir(path);
                    }
                    continue;
                }
                if path == marker {
                    continue;
                }
                if first_run {
                    let _ = std::fs::File::options().write(true).open(path).and_then(|f| f.set_modified(now));
                    continue;
                }
                let Ok(meta) = entry.metadata() else { continue };
                let old = meta.modified().ok().and_then(|t| now.duration_since(t).ok()).is_some_and(|age| age > retention());
                if old && std::fs::remove_file(path).is_ok() {
                    removed.0 += 1;
                    removed.1 += meta.len();
                }
            }
            if first_run {
                let _ = std::fs::write(&marker, RETENTION_MARKER_TEXT);
            }
        }
        removed
    })
    .await
    .unwrap_or_default()
}

// How much of a buddy's pledge we've used (received_bytes) against how
// much they've actually pledged us (pledged_bytes). Keyed by the buddy's
// Iroh node id (EndpointId's string form).
#[derive(Clone, Copy, Default)]
pub struct PledgeState {
    pub pledged_bytes: u64,
    pub received_bytes: u64,
}

// Shared between the accept loop (enforces the pledge on incoming data)
// and the outbound poll loop in main.rs (refreshes pledged_bytes from the
// API every 30s). A plain std::sync::Mutex is fine: every critical section
// is a quick map read/write with no .await inside it.
pub type PledgeBook = Arc<Mutex<HashMap<String, PledgeState>>>;

// received_bytes must survive restarts — otherwise a buddy could get a
// fresh budget just by waiting for us to redeploy. Persisted as plain JSON
// at DATA_DIR/usage.json: { "<node_id>": <received_bytes> }. pledged_bytes
// itself isn't persisted — it's re-learned from the API on every poll.
pub async fn load_usage_ledger(data_dir: &Path) -> HashMap<String, u64> {
    match tokio::fs::read(data_dir.join("usage.json")).await {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

/// What each buddy actually has stored with us right now: the total size
/// of their live files under BUDDY_FILES_DIR/<their node id>/ (not
/// `.versions/` backup slots or half-received uploads — the same things
/// the pledge counts). Used at startup to correct the saved ledger, which
/// is a running total and can drift: files removed or a folder reset by
/// hand, an older client's bookkeeping, a crash between writing a file and
/// saving the ledger.
pub async fn usage_from_disk(buddy_files_dir: &Path) -> HashMap<String, u64> {
    let mut usage = HashMap::new();
    let Ok(mut entries) = tokio::fs::read_dir(buddy_files_dir).await else { return usage };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') || !entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let live: u64 = list_sender_files(&entry.path()).await.iter().filter(|f| !f.deleted).map(|f| f.size).sum();
        usage.insert(name, live);
    }
    usage
}

pub async fn save_usage_ledger(data_dir: &Path, book: &PledgeBook) -> Result<()> {
    let snapshot: HashMap<String, u64> = {
        let book = book.lock().unwrap();
        book.iter().map(|(id, state)| (id.clone(), state.received_bytes)).collect()
    };
    let json = serde_json::to_vec(&snapshot)?;
    tokio::fs::write(data_dir.join("usage.json"), json).await?;
    Ok(())
}

/// Accept-loop entry point for one incoming connection. A buddy's client
/// opens one bidirectional stream per request (Ping, Put, Delete, List, or
/// Get — see protocol.rs), potentially many of them over the lifetime of
/// one connection (one Put per changed file in a backup cycle), so this
/// keeps accepting streams until the peer closes the connection rather
/// than handling just one and returning.
///
/// Storage is scoped by sender: everything a given buddy sends us lives
/// under BUDDY_FILES_DIR/<their node id>/<path they gave us>, and List/Get only
/// ever look inside that one sender's own directory — a buddy can never
/// see or fetch what another buddy stored with us.
pub async fn handle_incoming(
    incoming: iroh::endpoint::Incoming,
    data_dir: PathBuf,
    buddy_files_dir: PathBuf,
    pledge_book: PledgeBook,
    bandwidth_book: BandwidthBook,
) -> Result<()> {
    let connecting = incoming.accept()?;
    let conn = connecting.await?;
    let remote = conn.remote_id();
    let remote_id = remote.to_string();
    let sender_dir = buddy_files_dir.join(&remote_id);
    // Read once per connection rather than per stream — the path a
    // connection settles on doesn't change mid-connection, and every
    // stream on it (one per file in a backup cycle) shares the same one.
    let quality = netinfo::connection_quality(&conn);

    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(_) => break, // peer closed the connection — normal end of a sync cycle
        };
        let data_dir = data_dir.clone();
        let buddy_files_dir = buddy_files_dir.clone();
        let sender_dir = sender_dir.clone();
        let pledge_book = pledge_book.clone();
        let bandwidth_book = bandwidth_book.clone();
        let remote_id = remote_id.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_stream(
                send,
                recv,
                data_dir,
                buddy_files_dir,
                sender_dir,
                remote_id.clone(),
                pledge_book,
                bandwidth_book,
                quality,
            )
            .await
            {
                tracing::warn!(from = %remote_id, ?err, "request from buddy failed");
            }
        });
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_stream(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    data_dir: PathBuf,
    buddy_files_dir: PathBuf,
    sender_dir: PathBuf,
    remote_id: String,
    pledge_book: PledgeBook,
    bandwidth_book: BandwidthBook,
    quality: ConnectionQuality,
) -> Result<()> {
    let request: SyncRequest =
        protocol::read_frame(&mut recv).await.context("failed to read request")?;

    match request {
        SyncRequest::Ping => {
            protocol::write_frame(&mut send, &SyncAck::ok()).await?;
        }
        SyncRequest::Hello => {
            protocol::write_frame(
                &mut send,
                &protocol::HelloResponse { protocol_version: protocol::PROTOCOL_VERSION },
            )
            .await?;
        }
        // v1 senders state the hash up front; v2 senders (PutStream) send
        // it after the bytes. Both are handled by the same streaming code.
        SyncRequest::Put { path, ciphertext_len, ciphertext_sha256 } => {
            handle_put(
                &mut send,
                &mut recv,
                &sender_dir,
                &remote_id,
                &pledge_book,
                &data_dir,
                &buddy_files_dir,
                &bandwidth_book,
                &quality,
                path,
                ciphertext_len,
                Some(ciphertext_sha256),
            )
            .await?;
        }
        SyncRequest::PutStream { path, ciphertext_len } => {
            handle_put(
                &mut send,
                &mut recv,
                &sender_dir,
                &remote_id,
                &pledge_book,
                &data_dir,
                &buddy_files_dir,
                &bandwidth_book,
                &quality,
                path,
                ciphertext_len,
                None,
            )
            .await?;
        }
        SyncRequest::PutResumable { path, upload_id, ciphertext_len } => {
            handle_put_resumable(
                &mut send,
                &mut recv,
                &sender_dir,
                &remote_id,
                &pledge_book,
                &data_dir,
                &buddy_files_dir,
                &bandwidth_book,
                &quality,
                path,
                upload_id,
                ciphertext_len,
            )
            .await?;
        }
        SyncRequest::Delete { path } => {
            handle_delete(&mut send, &sender_dir, &remote_id, &pledge_book, &data_dir, path).await?;
        }
        SyncRequest::List => {
            handle_list(&mut send, &sender_dir).await?;
        }
        SyncRequest::ListStream => {
            let files = list_sender_files(&sender_dir).await;
            let mut chunks = files.chunks(protocol::LIST_CHUNK_ENTRIES).peekable();
            if chunks.peek().is_none() {
                protocol::write_frame(&mut send, &protocol::ListChunk { files: Vec::new(), done: true }).await?;
            }
            while let Some(chunk) = chunks.next() {
                let done = chunks.peek().is_none();
                // ListEntry isn't Clone; rebuild the slice's entries.
                let files = chunk
                    .iter()
                    .map(|e| ListEntry { path: e.path.clone(), size: e.size, deleted: e.deleted })
                    .collect();
                protocol::write_frame(&mut send, &protocol::ListChunk { files, done }).await?;
            }
        }
        SyncRequest::Get { path } => {
            handle_get(&mut send, &sender_dir, path, &data_dir, &bandwidth_book, &quality).await?;
        }
        SyncRequest::DiskStats => {
            handle_disk_stats(&mut send, &buddy_files_dir, &pledge_book).await?;
        }
        SyncRequest::ListVersions { path } => {
            handle_list_versions(&mut send, &sender_dir, path).await?;
        }
        SyncRequest::PurgeDeleted { path } => {
            handle_purge_deleted(&mut send, &sender_dir, &remote_id, path).await?;
        }
        SyncRequest::GetVersion { path, version } => {
            handle_get_version(&mut send, &sender_dir, path, version, &data_dir, &bandwidth_book, &quality)
                .await?;
        }
    }

    send.stopped().await.ok();
    Ok(())
}

// Reject anything that would escape the sender's own directory — an
// absolute path or any ".." component. A malicious or buggy buddy client
// sending path: "../../etc/passwd" should get "invalid path", not a write
// outside BUDDY_FILES_DIR/<their id>/. Also reused by restore.rs, which joins
// paths from a buddy's own List response the same way.
pub(crate) fn safe_join(base: &Path, rel: &str) -> Option<PathBuf> {
    let rel_path = Path::new(rel);
    if rel_path.is_absolute() {
        return None;
    }
    if rel_path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return None;
    }
    Some(base.join(rel_path))
}

/// Where an admitted upload goes, and what it replaces (for undoing the
/// pledge reservation if it doesn't complete).
struct Admitted {
    dest: PathBuf,
    previous_size: u64,
}

/// The checks every upload passes before a byte of it is read: size, path,
/// real disk space, then the pledge, which it also reserves (give it back
/// with `release_pledge` if the upload doesn't complete). `already_have` is
/// what a resumed upload already holds on disk, so only the rest needs room.
#[allow(clippy::too_many_arguments)]
async fn admit_put(
    sender_dir: &Path,
    remote_id: &str,
    pledge_book: &PledgeBook,
    buddy_files_dir: &Path,
    path: &str,
    ciphertext_len: u64,
    already_have: u64,
) -> std::result::Result<Admitted, PutRejectReason> {
    if ciphertext_len > protocol::MAX_FILE_BYTES {
        return Err(PutRejectReason::TooLarge);
    }
    let Some(dest) = safe_join(sender_dir, path) else {
        return Err(PutRejectReason::InvalidPath);
    };

    // If we already have a file at this path, only the *delta* against its
    // current size should count against the pledge — otherwise every
    // re-send of an unchanged-size file would eat into the budget again.
    // Note this slightly undercounts real disk growth while a path's
    // backup slots are still filling up (an overwrite moves the old
    // content into .versions/ rather than freeing it — see
    // rotate_versions), since the pledge math below still assumes the
    // previous size is reclaimed. Once a path has churned through all
    // MAX_BACKUP_VERSIONS slots that's true again (the oldest slot really
    // is freed on every rotation after that), and either way the real-disk
    // floor just below is what actually prevents the disk from filling —
    // this delta is only ever used to decide whether a pledge is exceeded.
    let previous_size = tokio::fs::metadata(&dest).await.map(|m| m.len()).unwrap_or(0);
    let incoming_delta = ciphertext_len.saturating_sub(previous_size).saturating_sub(already_have);

    // The real disk guard, ahead of the pledge check below: a pledge is
    // just a number this host agreed to over the API, so a buddy honoring
    // their own pledge perfectly can still arrive at a disk that's full
    // for some other reason (an over-generous pledge, something else on
    // the same volume). Checked first so a failure here reads as "no
    // room" rather than the more specific "pledge exceeded".
    if incoming_delta > 0 && !disk_has_room_for(buddy_files_dir, incoming_delta).await {
        tracing::warn!(
            from = %remote_id,
            path = %path,
            attempted_bytes = ciphertext_len,
            "rejected file — not enough real disk space left on this host"
        );
        return Err(PutRejectReason::DiskFull);
    }

    let mut book = pledge_book.lock().unwrap();
    let state = book.entry(remote_id.to_string()).or_default();
    let projected = state.received_bytes.saturating_sub(previous_size).saturating_add(ciphertext_len);
    if projected > state.pledged_bytes {
        tracing::warn!(
            from = %remote_id,
            path = %path,
            attempted_bytes = ciphertext_len,
            pledged_bytes = state.pledged_bytes,
            received_bytes = state.received_bytes,
            "rejected file — would exceed this buddy's pledge"
        );
        return Err(PutRejectReason::PledgeExceeded);
    }
    state.received_bytes = projected;
    Ok(Admitted { dest, previous_size })
}

/// Undoes admit_put's pledge reservation for an upload that didn't land.
fn release_pledge(pledge_book: &PledgeBook, remote_id: &str, ciphertext_len: u64, previous_size: u64) {
    let mut book = pledge_book.lock().unwrap();
    if let Some(state) = book.get_mut(remote_id) {
        state.received_bytes = state.received_bytes.saturating_sub(ciphertext_len).saturating_add(previous_size);
    }
}

/// Moves a fully received, hash-checked upload from `tmp` into place
/// (keeping what it replaces as a backup version) and records it. On
/// error nothing is acked; the caller releases the pledge.
#[allow(clippy::too_many_arguments)]
async fn commit_upload(
    tmp: &Path,
    dest: &Path,
    sender_dir: &Path,
    path: &str,
    data_dir: &Path,
    pledge_book: &PledgeBook,
    bandwidth_book: &BandwidthBook,
    quality: &ConnectionQuality,
    bytes_received: u64,
) -> Result<()> {
    // Protect whatever was there before this overwrite — a buddy's
    // backup cycle only Puts a path when their local copy actually
    // changed, so any existing `dest` here is genuinely being replaced,
    // not just re-sent unchanged.
    rotate_versions(sender_dir, path).await;

    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await.context("failed to create directory for incoming file")?;
    }
    tokio::fs::rename(tmp, dest).await.context("failed to store incoming file")?;

    if let Err(err) = save_usage_ledger(data_dir, pledge_book).await {
        // Don't fail the exchange over a ledger write hiccup — worst
        // case we under-persist by one file's worth and a restart
        // re-allows it, which is the safe direction to err in.
        tracing::warn!(?err, "failed to persist usage ledger");
    }
    crate::bandwidth::record(data_dir, bandwidth_book, quality, bytes_received).await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_put(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    sender_dir: &Path,
    remote_id: &str,
    pledge_book: &PledgeBook,
    data_dir: &Path,
    buddy_files_dir: &Path,
    bandwidth_book: &BandwidthBook,
    quality: &ConnectionQuality,
    path: String,
    ciphertext_len: u64,
    expected_sha256: Option<String>,
) -> Result<()> {
    let admitted =
        match admit_put(sender_dir, remote_id, pledge_book, buddy_files_dir, &path, ciphertext_len, 0).await {
            Ok(a) => a,
            Err(reason) => {
                reject_without_reading_body(recv, send, reason).await?;
                return Ok(());
            }
        };
    let rollback = || release_pledge(pledge_book, remote_id, ciphertext_len, admitted.previous_size);

    // Stream the body into a temp file in this buddy's own folder (same
    // filesystem, so the final move is an atomic rename), hashing as it
    // arrives. Memory use is one buffer, whatever the file size — this
    // used to read the whole file into RAM.
    let tmp = match incoming_tmp_path(sender_dir).await {
        Ok(tmp) => tmp,
        Err(err) => {
            rollback();
            return Err(err);
        }
    };
    let received = receive_body(recv, &tmp, ciphertext_len).await;
    let actual_hash = match received {
        Ok(hash) => hash,
        Err(err) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            rollback();
            return Err(err).context("failed to read file bytes");
        }
    };

    // v2 (PutStream): the hash follows the bytes.
    let expected = match expected_sha256 {
        Some(hash) => hash,
        None => match protocol::read_frame::<protocol::PutTrailer>(recv).await {
            Ok(t) => t.ciphertext_sha256,
            Err(err) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                rollback();
                return Err(err).context("failed to read upload trailer");
            }
        },
    };
    if actual_hash != expected {
        let _ = tokio::fs::remove_file(&tmp).await;
        rollback();
        protocol::write_frame(send, &SyncAck::err("hash mismatch")).await?;
        return Ok(());
    }

    if let Err(err) = commit_upload(
        &tmp,
        &admitted.dest,
        sender_dir,
        &path,
        data_dir,
        pledge_book,
        bandwidth_book,
        quality,
        ciphertext_len,
    )
    .await
    {
        let _ = tokio::fs::remove_file(&tmp).await;
        rollback();
        return Err(err);
    }

    protocol::write_frame(send, &SyncAck::ok()).await?;
    tracing::info!(from = %remote_id, path = %path, bytes = ciphertext_len, "stored file from buddy");
    Ok(())
}

// Partial resumable uploads (PutResumable) live under .incoming/resume/,
// one pair of files per path: `<key>.part` (the bytes so far) and
// `<key>.json` (which upload they belong to). Unlike ordinary staging files
// they survive a restart, since surviving interruptions is their point;
// clear_incoming drops them once they're RESUME_KEEP_DAYS old.
const RESUME_DIR: &str = "resume";
const RESUME_KEEP_DAYS: u64 = 7;

#[derive(Serialize, Deserialize, PartialEq)]
struct PartialUpload {
    path: String,
    upload_id: String,
    ciphertext_len: u64,
}

fn resume_paths(sender_dir: &Path, path: &str) -> (PathBuf, PathBuf) {
    // Keyed by a hash of the path: flat, fixed-length names, whatever the
    // path looks like.
    let key = &hex::encode(Sha256::digest(path.as_bytes()))[..32];
    let dir = sender_dir.join(INCOMING_DIR).join(RESUME_DIR);
    (dir.join(format!("{key}.part")), dir.join(format!("{key}.json")))
}

/// Partials being written right now. A dropped connection's handler can
/// sit in a read for up to the idle timeout before it notices; if the
/// sender reconnects sooner, a second handler appending to the same
/// partial would interleave bytes (caught by the hash, but the upload would
/// be wasted). So one upload per path at a time; a second is told to retry.
static RESUMABLE_IN_PROGRESS: std::sync::LazyLock<Mutex<std::collections::HashSet<PathBuf>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));

struct InProgress(PathBuf);

impl InProgress {
    fn claim(part: &Path) -> Option<Self> {
        RESUMABLE_IN_PROGRESS.lock().unwrap().insert(part.to_path_buf()).then(|| Self(part.to_path_buf()))
    }
}

impl Drop for InProgress {
    fn drop(&mut self) {
        RESUMABLE_IN_PROGRESS.lock().unwrap().remove(&self.0);
    }
}

/// How many bytes of this exact upload are already here. A partial from a
/// different upload of the same path (the sender re-encrypted, so its
/// bytes no longer line up) is thrown away.
async fn partial_bytes(sender_dir: &Path, wanted: &PartialUpload) -> u64 {
    let (part, meta) = resume_paths(sender_dir, &wanted.path);
    let current = tokio::fs::read(&meta).await.ok().and_then(|b| serde_json::from_slice::<PartialUpload>(&b).ok());
    let size = tokio::fs::metadata(&part).await.map(|m| m.len()).ok();
    match (current, size) {
        (Some(current), Some(size)) if current == *wanted && size <= wanted.ciphertext_len => size,
        _ => {
            let _ = tokio::fs::remove_file(&part).await;
            let _ = tokio::fs::remove_file(&meta).await;
            0
        }
    }
}

/// A refusal of a PutResumable: the same STOP_SENDING code as other
/// refusals, plus a PutResumeReply (the sender is waiting for one before
/// it sends any bytes, so it does get to read this).
async fn reject_resumable(
    recv: &mut iroh::endpoint::RecvStream,
    send: &mut iroh::endpoint::SendStream,
    reason: PutRejectReason,
) -> Result<()> {
    recv.stop(iroh::endpoint::VarInt::from_u32(reason.code())).ok();
    let reply = protocol::PutResumeReply {
        offset: None,
        error: Some(reason.message().to_string()),
        reject_code: Some(reason.code() as u64),
    };
    protocol::write_frame(send, &reply).await
}

#[allow(clippy::too_many_arguments)]
async fn handle_put_resumable(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    sender_dir: &Path,
    remote_id: &str,
    pledge_book: &PledgeBook,
    data_dir: &Path,
    buddy_files_dir: &Path,
    bandwidth_book: &BandwidthBook,
    quality: &ConnectionQuality,
    path: String,
    upload_id: String,
    ciphertext_len: u64,
) -> Result<()> {
    if safe_join(sender_dir, &path).is_none() {
        reject_resumable(recv, send, PutRejectReason::InvalidPath).await?;
        return Ok(());
    }
    let (part, meta) = resume_paths(sender_dir, &path);
    let Some(_claim) = InProgress::claim(&part) else {
        // Not a refusal (no reject_code): the sender keeps its copy and
        // tries again next cycle.
        let reply = protocol::PutResumeReply {
            offset: None,
            error: Some("an earlier upload of this file is still finishing here — will retry".to_string()),
            reject_code: None,
        };
        recv.stop(iroh::endpoint::VarInt::from_u32(0)).ok();
        protocol::write_frame(send, &reply).await?;
        return Ok(());
    };
    let wanted = PartialUpload { path: path.clone(), upload_id, ciphertext_len };
    let offset = partial_bytes(sender_dir, &wanted).await;

    let admitted =
        match admit_put(sender_dir, remote_id, pledge_book, buddy_files_dir, &path, ciphertext_len, offset).await {
            Ok(a) => a,
            Err(reason) => {
                reject_resumable(recv, send, reason).await?;
                return Ok(());
            }
        };
    let rollback = || release_pledge(pledge_book, remote_id, ciphertext_len, admitted.previous_size);

    let prepared = async {
        if let Some(dir) = part.parent() {
            tokio::fs::create_dir_all(dir).await.context("failed to create upload staging folder")?;
        }
        tokio::fs::write(&meta, serde_json::to_vec(&wanted)?).await.context("failed to record upload")?;
        anyhow::Ok(())
    }
    .await;
    if let Err(err) = prepared {
        rollback();
        return Err(err);
    }

    protocol::write_frame(send, &protocol::PutResumeReply { offset: Some(offset), ..Default::default() }).await?;
    if offset > 0 {
        tracing::info!(from = %remote_id, path = %path, offset, total = ciphertext_len, "resuming upload from buddy");
    }

    // The hash covers the whole file: what's already here, then the rest
    // as it arrives. A dropped connection keeps the partial for next time.
    let actual_hash = match append_body(recv, &part, offset, ciphertext_len - offset).await {
        Ok(hash) => hash,
        Err(err) => {
            rollback();
            return Err(err).context("failed to read file bytes (kept what arrived, to resume)");
        }
    };
    let expected = match protocol::read_frame::<protocol::PutTrailer>(recv).await {
        Ok(t) => t.ciphertext_sha256,
        Err(err) => {
            rollback();
            return Err(err).context("failed to read upload trailer");
        }
    };
    if actual_hash != expected {
        let _ = tokio::fs::remove_file(&part).await;
        let _ = tokio::fs::remove_file(&meta).await;
        rollback();
        protocol::write_frame(send, &SyncAck::err("hash mismatch")).await?;
        return Ok(());
    }

    if let Err(err) = commit_upload(
        &part,
        &admitted.dest,
        sender_dir,
        &path,
        data_dir,
        pledge_book,
        bandwidth_book,
        quality,
        ciphertext_len - offset,
    )
    .await
    {
        rollback();
        return Err(err);
    }
    let _ = tokio::fs::remove_file(&meta).await;

    protocol::write_frame(send, &SyncAck::ok()).await?;
    tracing::info!(from = %remote_id, path = %path, bytes = ciphertext_len, resumed_from = offset, "stored file from buddy");
    Ok(())
}

/// Hashes the first `have` bytes already in `part`, then appends `len` more
/// from `recv`, returning the SHA-256 of the whole. Flushed before
/// returning; on error, whatever arrived is kept (flushed) for a resume.
async fn append_body(recv: &mut iroh::endpoint::RecvStream, part: &Path, have: u64, len: u64) -> Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; IO_CHUNK];
    if have > 0 {
        let mut existing = tokio::fs::File::open(part).await.context("failed to open partial upload")?;
        let mut left = have;
        while left > 0 {
            let n = existing.read(&mut buf[..left.min(IO_CHUNK as u64) as usize]).await?;
            if n == 0 {
                anyhow::bail!("partial upload is shorter than recorded");
            }
            hasher.update(&buf[..n]);
            left -= n as u64;
        }
    }
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(part)
        .await
        .context("failed to open partial upload for writing")?;
    let mut remaining = len;
    let result = async {
        while remaining > 0 {
            let n = remaining.min(IO_CHUNK as u64) as usize;
            recv.read_exact(&mut buf[..n]).await.context("connection ended mid-file")?;
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n]).await.context("failed to write incoming file")?;
            remaining -= n as u64;
        }
        anyhow::Ok(())
    }
    .await;
    // Flush either way: on success before acking, on failure so the next
    // resume's offset (the file's length) only counts bytes really stored.
    file.sync_all().await.context("failed to flush incoming file")?;
    result?;
    Ok(hex::encode(hasher.finalize()))
}

// Every early-rejection branch above decides *before* reading the
// incoming file body off `recv` — deliberately, so we don't waste time
// and bandwidth downloading megabytes/gigabytes of a file we're about to
// throw away. But the sender (put_one_file in backup.rs) writes its
// entire ciphertext body before it ever tries to read our ack, so if we
// just write the rejection ack without doing anything about the body
// they're still sending, their `send.write_all(&ciphertext)` blocks
// forever waiting for QUIC flow-control credit we'll never grant (we're
// not reading), while we sit in handle_stream's `send.stopped().await`
// waiting for them to finish sending — a real deadlock, not just a slow
// cycle. `RecvStream::stop()` sends a QUIC STOP_SENDING frame, which
// makes their blocked write fail immediately instead of hanging, so they
// can log the failure and move on to the next file next cycle. The error
// code it carries is `reason`'s own code (see PutRejectReason), so the
// sender — which generally never gets to read the string ack below, since
// it's usually still mid-write when the stop lands — can still learn
// *why*, not just that it failed.
async fn reject_without_reading_body(
    recv: &mut iroh::endpoint::RecvStream,
    send: &mut iroh::endpoint::SendStream,
    reason: PutRejectReason,
) -> Result<()> {
    recv.stop(iroh::endpoint::VarInt::from_u32(reason.code())).ok();
    protocol::write_frame(send, &SyncAck::err(reason.message())).await
}

// Uploads in progress live here, inside the sender's own folder: same
// filesystem as the final location (so moving into place is an atomic
// rename), and never listed as files (see collect_files). Leftovers from an
// interrupted upload are cleared at startup (clear_incoming).
const INCOMING_DIR: &str = ".incoming";
const IO_CHUNK: usize = 256 * 1024;

async fn incoming_tmp_path(sender_dir: &Path) -> Result<PathBuf> {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = sender_dir.join(INCOMING_DIR);
    tokio::fs::create_dir_all(&dir).await.context("failed to create upload staging folder")?;
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(dir.join(format!("{}-{n}.part", std::process::id())))
}

/// Reads exactly `len` bytes from `recv` into a new file at `path`,
/// returning their SHA-256. Flushed to disk before returning, so a file
/// isn't acknowledged until it's actually stored.
async fn receive_body(recv: &mut iroh::endpoint::RecvStream, path: &Path, len: u64) -> Result<String> {
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::File::create(path).await.context("failed to create upload file")?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; IO_CHUNK];
    let mut remaining = len;
    while remaining > 0 {
        let n = remaining.min(IO_CHUNK as u64) as usize;
        recv.read_exact(&mut buf[..n]).await.context("connection ended mid-file")?;
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n]).await.context("failed to write incoming file")?;
        remaining -= n as u64;
    }
    file.sync_all().await.context("failed to flush incoming file")?;
    Ok(hex::encode(hasher.finalize()))
}

/// Removes leftovers of uploads interrupted by a restart or crash, except
/// resumable partials (`.incoming/resume/`), which are kept for the sender
/// to finish unless they're RESUME_KEEP_DAYS old.
pub async fn clear_incoming(buddy_files_dir: &Path) {
    let Ok(mut entries) = tokio::fs::read_dir(buddy_files_dir).await else { return };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let staging = entry.path().join(INCOMING_DIR);
        let Ok(mut items) = tokio::fs::read_dir(&staging).await else { continue };
        while let Ok(Some(item)) = items.next_entry().await {
            if item.file_name() == RESUME_DIR {
                remove_older_than(&item.path(), RESUME_KEEP_DAYS).await;
            } else if item.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                let _ = tokio::fs::remove_dir_all(item.path()).await;
            } else {
                let _ = tokio::fs::remove_file(item.path()).await;
            }
        }
    }
}

/// Deletes files directly in `dir` not modified for `days` days.
pub async fn remove_older_than(dir: &Path, days: u64) {
    let Ok(mut items) = tokio::fs::read_dir(dir).await else { return };
    let max_age = std::time::Duration::from_secs(days * 24 * 60 * 60);
    while let Ok(Some(item)) = items.next_entry().await {
        let old = item
            .metadata()
            .await
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > max_age);
        if old {
            let _ = tokio::fs::remove_file(item.path()).await;
        }
    }
}

/// Streams a stored file to `send` after an ok ack, in bounded memory.
/// Returns the number of bytes sent.
async fn send_file(send: &mut iroh::endpoint::SendStream, src: &Path) -> Result<Option<u64>> {
    use tokio::io::AsyncReadExt;
    let Ok(mut file) = tokio::fs::File::open(src).await else { return Ok(None) };
    protocol::write_frame(send, &SyncAck::ok()).await?;
    let mut buf = vec![0u8; IO_CHUNK];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buf).await.context("failed to read stored file")?;
        if n == 0 {
            break;
        }
        send.write_all(&buf[..n]).await.context("failed to send file bytes")?;
        total += n as u64;
    }
    // Without finish(), the stream's FIN never goes out and the requester
    // (restore.rs) waits forever for the end of the file.
    send.finish().context("failed to finish send stream")?;
    Ok(Some(total))
}

async fn handle_delete(
    send: &mut iroh::endpoint::SendStream,
    sender_dir: &Path,
    remote_id: &str,
    pledge_book: &PledgeBook,
    data_dir: &Path,
    path: String,
) -> Result<()> {
    let Some(target) = safe_join(sender_dir, &path) else {
        protocol::write_frame(send, &SyncAck::err("invalid path")).await?;
        return Ok(());
    };

    let freed = tokio::fs::metadata(&target).await.map(|m| m.len()).unwrap_or(0);

    // A "delete" doesn't destroy the content — it moves it into the same
    // backup-slot rotation an overwrite goes through, so an accidental
    // local delete (the far more common case than a deliberate one) is
    // still recoverable from a backup slot, not actually gone. If that
    // rotation couldn't happen for some reason, fall back to a plain
    // remove so the live path is still reliably cleared either way.
    rotate_versions(sender_dir, &path).await;
    match tokio::fs::remove_file(&target).await {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {} // idempotent: already gone (or just rotated away) is fine
        Err(err) => {
            protocol::write_frame(send, &SyncAck::err(format!("failed to delete: {err}"))).await?;
            return Ok(());
        }
    }

    if freed > 0 {
        {
            let mut book = pledge_book.lock().unwrap();
            if let Some(state) = book.get_mut(remote_id) {
                state.received_bytes = state.received_bytes.saturating_sub(freed);
            }
        }
        if let Err(err) = save_usage_ledger(data_dir, pledge_book).await {
            tracing::warn!(?err, "failed to persist usage ledger after delete");
        }
    }

    protocol::write_frame(send, &SyncAck::ok()).await?;
    tracing::info!(from = %remote_id, path = %path, "deleted file for buddy");
    Ok(())
}

async fn handle_list(send: &mut iroh::endpoint::SendStream, sender_dir: &Path) -> Result<()> {
    let files = list_sender_files(sender_dir).await;
    protocol::write_frame(send, &ListResponse { files }).await?;
    Ok(())
}

// Answers DiskStats with this host's real numbers — see
// DiskStatsResponse's doc comment for why this exists (lets the asking
// buddy's dashboard show "what do they actually have" next to "what did
// they pledge" instead of just trusting the pledge).
async fn handle_disk_stats(
    send: &mut iroh::endpoint::SendStream,
    buddy_files_dir: &Path,
    pledge_book: &PledgeBook,
) -> Result<()> {
    let pledged_out_total_bytes: u64 =
        { pledge_book.lock().unwrap().values().map(|s| s.pledged_bytes).sum() };

    // The disk a buddy's files actually land on (BUDDY_FILES_DIR), which may
    // be a different drive from DATA_DIR's config/state.
    let dir_owned = buddy_files_dir.to_path_buf();
    let stats = tokio::task::spawn_blocking(move || fs4::statvfs(&dir_owned)).await;

    let response = match stats {
        Ok(Ok(stats)) => {
            let total_bytes = stats.total_space();
            let available_bytes = stats.available_space();
            DiskStatsResponse {
                total_bytes,
                available_bytes,
                used_bytes: total_bytes.saturating_sub(available_bytes),
                pledged_out_total_bytes,
            }
        }
        // Couldn't read disk stats — report zeros rather than failing the
        // whole request, so the asking dashboard can show "unknown"
        // instead of an error.
        _ => DiskStatsResponse {
            total_bytes: 0,
            available_bytes: 0,
            used_bytes: 0,
            pledged_out_total_bytes,
        },
    };

    protocol::write_frame(send, &response).await?;
    Ok(())
}

/// Everything stored under one sender's directory (received/<node id>/),
/// as the same ListEntry shape the List protocol request returns. Shared
/// with dashboard.rs so the local status page can show "what have they
/// backed up with us" without duplicating the directory walk.
///
/// Includes deleted-but-recoverable paths (live file gone, but a slot
/// still exists under .versions/) as entries with `deleted: true`, so a
/// file someone deleted doesn't just vanish from the list — it's still
/// reachable via History/restore-a-version, same as an overwritten file
/// is. Without this, rotate_versions() on delete faithfully keeps the
/// backup slot on disk, but nothing in the browser ever offered a way
/// back to it once the live copy was gone.
pub async fn list_sender_files(sender_dir: &Path) -> Vec<ListEntry> {
    let mut files = Vec::new();
    collect_files(sender_dir, sender_dir, &mut files).await;

    let live: std::collections::HashSet<&str> = files.iter().map(|f| f.path.as_str()).collect();
    let mut deleted = Vec::new();
    collect_deleted(sender_dir, &versions_root(sender_dir), &live, &mut deleted).await;
    files.extend(deleted);

    files
}

// Walks .versions/ looking for paths that no longer have a live file —
// i.e. the file was deleted, not just overwritten. Each one becomes a
// single `deleted: true` ListEntry (deduped across its remaining backup
// slots), sized from whichever slot is newest.
fn collect_deleted<'a>(
    sender_dir: &'a Path,
    dir: &'a Path,
    live: &'a std::collections::HashSet<&'a str>,
    out: &'a mut Vec<ListEntry>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
    Box::pin(async move {
        let Ok(mut entries) = tokio::fs::read_dir(dir).await else { return };
        let mut seen = std::collections::HashSet::new();
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let Ok(file_type) = entry.file_type().await else { continue };
            if file_type.is_dir() {
                collect_deleted(sender_dir, &path, live, out).await;
            } else if file_type.is_file() {
                let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else { continue };
                // Version slots are named "<original file name>.v<N>" —
                // strip that suffix to get back the original relative path.
                let Some(stripped) = file_name.rsplit_once(".v").and_then(|(name, slot)| {
                    slot.parse::<u32>().ok().map(|_| name)
                }) else {
                    continue;
                };
                let versions_dir = versions_root(sender_dir);
                let rel_dir = path.parent().unwrap_or(&path).strip_prefix(&versions_dir).unwrap_or(Path::new(""));
                let rel = rel_dir.join(stripped).to_string_lossy().replace('\\', "/");

                if live.contains(rel.as_str()) || !seen.insert(rel.clone()) {
                    continue;
                }
                let size = entry.metadata().await.map(|m| m.len()).unwrap_or(0);
                out.push(ListEntry { path: rel, size, deleted: true });
            }
        }
    })
}

// Recursive async fn needs boxing in stable Rust.
fn collect_files<'a>(
    base: &'a Path,
    dir: &'a Path,
    out: &'a mut Vec<ListEntry>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
    Box::pin(async move {
        let Ok(mut entries) = tokio::fs::read_dir(dir).await else { return };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let Ok(file_type) = entry.file_type().await else { continue };
            if file_type.is_dir() {
                // Backup-version slots live under .versions/ — they're not
                // restorable the normal way (ListVersions/GetVersion only),
                // so they shouldn't show up as if they were live files.
                let name = path.file_name().and_then(|n| n.to_str());
                if name == Some(".versions") || name == Some(INCOMING_DIR) {
                    continue;
                }
                collect_files(base, &path, out).await;
            } else if file_type.is_file() {
                let size = entry.metadata().await.map(|m| m.len()).unwrap_or(0);
                let rel =
                    path.strip_prefix(base).unwrap_or(&path).to_string_lossy().replace('\\', "/");
                out.push(ListEntry { path: rel, size, deleted: false });
            }
        }
    })
}

async fn handle_get(
    send: &mut iroh::endpoint::SendStream,
    sender_dir: &Path,
    path: String,
    data_dir: &Path,
    bandwidth_book: &BandwidthBook,
    quality: &ConnectionQuality,
) -> Result<()> {
    let Some(src) = safe_join(sender_dir, &path) else {
        protocol::write_frame(send, &SyncAck::err("invalid path")).await?;
        return Ok(());
    };

    match send_file(send, &src).await? {
        Some(sent) => crate::bandwidth::record(data_dir, bandwidth_book, quality, sent).await,
        None => protocol::write_frame(send, &SyncAck::err("not found")).await?,
    }
    Ok(())
}

/// Removes every backup copy of a deleted file (dashboard's "Delete
/// permanently"), then any folders under .versions/ that leaves empty.
/// Refused while the live file exists: only copies of something the sender
/// already deleted can go, never a file they still have.
async fn handle_purge_deleted(
    send: &mut iroh::endpoint::SendStream,
    sender_dir: &Path,
    remote_id: &str,
    path: String,
) -> Result<()> {
    let Some(live) = safe_join(sender_dir, &path) else {
        protocol::write_frame(send, &SyncAck::err("invalid path")).await?;
        return Ok(());
    };
    if tokio::fs::metadata(&live).await.is_ok() {
        protocol::write_frame(
            send,
            &SyncAck::err("this file still exists on your buddy's side — only deleted files can be removed permanently"),
        )
        .await?;
        return Ok(());
    }
    let mut removed = 0u32;
    for slot in 1..=MAX_BACKUP_VERSIONS {
        let Some(vp) = version_path(sender_dir, &path, slot) else { break };
        if tokio::fs::remove_file(&vp).await.is_ok() {
            removed += 1;
        }
    }
    // Tidy emptied folders up to (not including) .versions/ itself.
    let versions = versions_root(sender_dir);
    if let Some(mut dir) = version_path(sender_dir, &path, 1).and_then(|p| p.parent().map(Path::to_path_buf)) {
        while dir != versions && dir.starts_with(&versions) && tokio::fs::remove_dir(&dir).await.is_ok() {
            let Some(parent) = dir.parent() else { break };
            dir = parent.to_path_buf();
        }
    }
    tracing::info!(from = %remote_id, path = %path, copies = removed, "permanently removed backup copies at buddy's request");
    protocol::write_frame(send, &SyncAck::ok()).await?;
    Ok(())
}

async fn handle_list_versions(
    send: &mut iroh::endpoint::SendStream,
    sender_dir: &Path,
    path: String,
) -> Result<()> {
    let mut versions = Vec::new();
    for slot in 1..=MAX_BACKUP_VERSIONS {
        let Some(vp) = version_path(sender_dir, &path, slot) else { break };
        if let Ok(meta) = tokio::fs::metadata(&vp).await {
            let kept = meta.modified().ok();
            let modified_unix =
                kept.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs());
            let expires_unix = kept.and_then(expires_unix);
            versions.push(VersionEntry { version: slot, size: meta.len(), modified_unix, expires_unix });
        }
    }
    protocol::write_frame(send, &ListVersionsResponse { versions }).await?;
    Ok(())
}

async fn handle_get_version(
    send: &mut iroh::endpoint::SendStream,
    sender_dir: &Path,
    path: String,
    version: u32,
    data_dir: &Path,
    bandwidth_book: &BandwidthBook,
    quality: &ConnectionQuality,
) -> Result<()> {
    let Some(src) = version_path(sender_dir, &path, version) else {
        protocol::write_frame(send, &SyncAck::err("invalid path")).await?;
        return Ok(());
    };

    match send_file(send, &src).await? {
        Some(sent) => crate::bandwidth::record(data_dir, bandwidth_book, quality, sent).await,
        None => protocol::write_frame(send, &SyncAck::err("not found")).await?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_age_days(path: &Path, days: u64) {
        let t = std::time::SystemTime::now() - std::time::Duration::from_secs(days * 24 * 60 * 60);
        std::fs::File::options().write(true).open(path).unwrap().set_modified(t).unwrap();
    }

    fn age_secs(path: &Path) -> u64 {
        std::fs::metadata(path).unwrap().modified().unwrap().elapsed().map(|d| d.as_secs()).unwrap_or(0)
    }

    // Copies older than the retention period go; recent ones stay. The
    // first run only re-dates copies made before retention existed.
    #[tokio::test]
    async fn backup_copies_expire_after_retention() {
        let root = std::env::temp_dir().join(format!("bb-retention-test-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&root).await;
        let versions = root.join("some-buddy").join(".versions");
        std::fs::create_dir_all(versions.join("photos/old-trip")).unwrap();
        let old = versions.join("photos/a.jpg.v1");
        let recent = versions.join("photos/b.jpg.v1");
        let nested = versions.join("photos/old-trip/c.jpg.v2");
        for f in [&old, &recent, &nested] {
            std::fs::write(f, vec![1u8; 100]).unwrap();
        }
        set_age_days(&old, 40);
        set_age_days(&nested, 40);

        // First run: nothing removed, old copies re-dated to now.
        assert_eq!(expire_versions(&root).await, (0, 0));
        assert!(old.exists() && age_secs(&old) < 60, "pre-retention copy re-dated, not removed");
        assert!(versions.join(RETENTION_MARKER).exists());

        // From then on, age counts.
        set_age_days(&old, VERSION_RETENTION_DAYS + 1);
        set_age_days(&nested, VERSION_RETENTION_DAYS + 1);
        set_age_days(&recent, VERSION_RETENTION_DAYS - 1);
        assert_eq!(expire_versions(&root).await, (2, 200));
        assert!(!old.exists() && !nested.exists());
        assert!(recent.exists(), "a copy inside the retention period stays");
        assert!(!versions.join("photos/old-trip").exists(), "emptied folder removed");
        assert!(versions.join(RETENTION_MARKER).exists());
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    // A new backup copy is dated when it was kept, not when it was uploaded.
    #[tokio::test]
    async fn a_new_backup_copy_is_dated_now() {
        let root = std::env::temp_dir().join(format!("bb-rotate-date-test-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&root).await;
        std::fs::create_dir_all(root.join("docs")).unwrap();
        let live = root.join("docs/report.pdf");
        std::fs::write(&live, b"uploaded long ago").unwrap();
        set_age_days(&live, 200);
        rotate_versions(&root, "docs/report.pdf").await;
        let slot = version_path(&root, "docs/report.pdf", 1).unwrap();
        assert!(slot.exists() && age_secs(&slot) < 60);
        assert!(versions_root(&root).join(RETENTION_MARKER).exists(), "a fresh .versions/ is marked right away");
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    // A restart clears half-finished ordinary uploads, but keeps resumable
    // partials for the sender to finish.
    #[tokio::test]
    async fn clear_incoming_keeps_resumable_partials() {
        let root = std::env::temp_dir().join(format!("bb-clear-incoming-test-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&root).await;
        let staging = root.join("some-buddy").join(INCOMING_DIR);
        tokio::fs::create_dir_all(staging.join(RESUME_DIR)).await.unwrap();
        tokio::fs::write(staging.join("123-0.part"), b"ordinary leftover").await.unwrap();
        tokio::fs::write(staging.join(RESUME_DIR).join("abc.part"), b"resumable").await.unwrap();
        tokio::fs::write(staging.join(RESUME_DIR).join("abc.json"), b"{}").await.unwrap();

        clear_incoming(&root).await;

        assert!(!staging.join("123-0.part").exists(), "ordinary staging is cleared");
        assert!(staging.join(RESUME_DIR).join("abc.part").exists(), "a fresh resumable partial is kept");
        assert!(staging.join(RESUME_DIR).join("abc.json").exists());
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    // The startup correction for a drifted usage ledger: only live files
    // count — not backup-version slots, half-received uploads, or the
    // folder marker at the top of BUDDY_FILES_DIR.
    #[tokio::test]
    async fn usage_from_disk_counts_only_live_files() {
        let root = std::env::temp_dir().join(format!("bb-usage-from-disk-test-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&root).await;
        let sender = root.join("buddyA");
        tokio::fs::create_dir_all(sender.join("photos")).await.unwrap();
        tokio::fs::create_dir_all(sender.join(".versions/photos")).await.unwrap();
        tokio::fs::create_dir_all(sender.join(INCOMING_DIR)).await.unwrap();
        tokio::fs::create_dir_all(root.join("buddyB")).await.unwrap();
        tokio::fs::write(root.join(".backup-buddies-id"), b"marker").await.unwrap();
        tokio::fs::write(sender.join("a.txt"), vec![0u8; 10]).await.unwrap();
        tokio::fs::write(sender.join("photos/b.jpg"), vec![0u8; 20]).await.unwrap();
        tokio::fs::write(sender.join(".versions/photos/b.jpg.v1"), vec![0u8; 500]).await.unwrap();
        tokio::fs::write(sender.join(INCOMING_DIR).join("partial"), vec![0u8; 700]).await.unwrap();

        let usage = usage_from_disk(&root).await;
        assert_eq!(usage.get("buddyA"), Some(&30));
        assert_eq!(usage.get("buddyB"), Some(&0));
        assert_eq!(usage.len(), 2);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    // Regression test for a deleted file disappearing from the dashboard's
    // file browser entirely (reported against a live setup: delete a file
    // locally, let it cycle, then "Files from <buddy>" just no longer
    // listed it at all — not even with a History button — despite
    // rotate_versions() correctly keeping its content under .versions/).
    #[tokio::test]
    async fn list_sender_files_surfaces_deleted_but_recoverable_paths() {
        let dir = std::env::temp_dir()
            .join(format!("bb-list-sender-files-test-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(dir.join("notes")).await.unwrap();
        tokio::fs::create_dir_all(dir.join(".versions/notes")).await.unwrap();

        // `hello.txt` is still live.
        tokio::fs::write(dir.join("hello.txt"), b"hi").await.unwrap();
        // `notes/wtf.txt` was deleted — rotate_versions() moved its old
        // content to slot 1 before the delete, so only the version slot
        // remains, no live file.
        tokio::fs::write(dir.join(".versions/notes/wtf.txt.v1"), b"old content").await.unwrap();

        let files = list_sender_files(&dir).await;

        let hello = files.iter().find(|f| f.path == "hello.txt").expect("hello.txt listed");
        assert!(!hello.deleted, "live file should not be marked deleted");

        let wtf = files
            .iter()
            .find(|f| f.path == "notes/wtf.txt")
            .expect("deleted file should still be listed, not silently dropped");
        assert!(wtf.deleted, "a path with no live file but a surviving version should be marked deleted");
        assert_eq!(wtf.size, "old content".len() as u64);

        // Exactly one entry for the deleted path, not one per surviving slot.
        assert_eq!(files.iter().filter(|f| f.path == "notes/wtf.txt").count(), 1);

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
