// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::bandwidth::BandwidthBook;
use crate::netinfo::{self, ConnectionQuality};
use crate::protocol::{self, DiskStatsResponse, PutRejectReason, SyncAck, SyncRequest};

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
// per-buddy pledge enforcement in admit_put below. Fails open (allows
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

/// A folder in BUDDY_FILES_DIR whose node id isn't one of our buddies'
/// devices any more is removed this long after it was first noticed.
/// Seen on a test device (2026-10-13): a buddy's client got a new node id
/// (moved to another machine with the same token), and what the old id
/// stored stayed here for good, counted against our disk, as a nameless
/// buddy card. An ended pairing leaves the same behind.
pub const ORPHAN_KEEP_DAYS: u64 = 30;

/// When each such folder was first noticed: DATA_DIR/orphans.json,
/// `{ "<node id>": <unix seconds> }`. Kept out of BUDDY_FILES_DIR so
/// nothing new shows up in anyone's listing.
fn orphans_path(data_dir: &Path) -> PathBuf {
    data_dir.join("orphans.json")
}

pub fn load_orphans(data_dir: &Path) -> HashMap<String, u64> {
    std::fs::read(orphans_path(data_dir)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

/// Marks folders whose node id isn't in `current` (every device of every
/// buddy, from a successful poll), unmarks ones whose device is back, and
/// removes those marked ORPHAN_KEEP_DAYS ago. Returns what was removed
/// (node id, bytes), so the caller can free it from the pledge book.
pub async fn sweep_orphans(
    data_dir: &Path,
    buddy_files_dir: &Path,
    current: &std::collections::HashSet<String>,
    now_unix: u64,
) -> Vec<(String, u64)> {
    let mut marks = load_orphans(data_dir);
    let mut removed = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let Ok(mut entries) = tokio::fs::read_dir(buddy_files_dir).await else { return removed };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') || !entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        seen.insert(name.clone());
        if current.contains(&name) {
            marks.remove(&name);
            continue;
        }
        let since = *marks.entry(name.clone()).or_insert(now_unix);
        if now_unix.saturating_sub(since) >= ORPHAN_KEEP_DAYS * 24 * 60 * 60 {
            let bytes = walkdir::WalkDir::new(entry.path())
                .into_iter()
                .flatten()
                .filter_map(|e| e.metadata().ok())
                .filter(|m| m.is_file())
                .map(|m| m.len())
                .sum();
            match tokio::fs::remove_dir_all(entry.path()).await {
                Ok(()) => {
                    marks.remove(&name);
                    removed.push((name, bytes));
                }
                Err(err) => tracing::warn!(node_id = %name, ?err, "couldn't remove a former buddy device's files"),
            }
        }
    }
    // Folders that went some other way (removed by hand) need no mark.
    marks.retain(|name, _| seen.contains(name));
    if let Ok(json) = serde_json::to_vec(&marks) {
        let _ = tokio::fs::write(orphans_path(data_dir), json).await;
    }
    removed
}

// How much of a buddy's pledge we've used (received_bytes) against how
// much they've actually pledged us (pledged_bytes). Keyed by the buddy's
// Iroh node id (EndpointId's string form), but a pledge is between two
// accounts, and one account can run several devices (one per container).
// Counted per device alone, each of them got the whole pledge: three
// containers on a 20 GB pairing could store 60 GB here. So account_id
// (from the API poll) groups a buddy's devices, and the pledge check adds
// up all of them. None until the first poll names the device's account.
#[derive(Clone, Default)]
pub struct PledgeState {
    pub pledged_bytes: u64,
    pub received_bytes: u64,
    pub account_id: Option<String>,
}

/// What `node_id`'s other devices (same buddy account) have stored with
/// us; 0 while its account isn't known yet.
fn received_by_other_devices(book: &HashMap<String, PledgeState>, node_id: &str) -> u64 {
    let Some(account) = book.get(node_id).and_then(|s| s.account_id.as_deref()) else { return 0 };
    book.iter()
        .filter(|(id, s)| id.as_str() != node_id && s.account_id.as_deref() == Some(account))
        .map(|(_, s)| s.received_bytes)
        .sum()
}

/// Everything counted against the pledge `node_id` falls under: its own
/// files plus its account's other devices'.
pub fn account_received_bytes(book: &HashMap<String, PledgeState>, node_id: &str) -> u64 {
    let own = book.get(node_id).map(|s| s.received_bytes).unwrap_or(0);
    own.saturating_add(received_by_other_devices(book, node_id))
}

/// The total we've promised to store for others: each buddy account's
/// pledge once, not once per device it runs.
pub fn pledged_out_total(book: &HashMap<String, PledgeState>) -> u64 {
    let mut seen = std::collections::HashSet::new();
    book.iter()
        .filter(|(id, s)| match &s.account_id {
            Some(account) => seen.insert(account.as_str()),
            None => seen.insert(id.as_str()),
        })
        .map(|(_, s)| s.pledged_bytes)
        .sum()
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

/// What each buddy actually has stored with us right now: the size of
/// their backup repository under BUDDY_FILES_DIR/<their node id>/.repo/,
/// old snapshots included, since it's all space this host is giving them
/// (not half-received uploads, or anything else in their folder). Used at
/// startup to correct the saved ledger, which is a running total and can
/// drift: files removed or a folder reset by hand, a crash between writing
/// a file and saving the ledger.
pub async fn usage_from_disk(buddy_files_dir: &Path) -> HashMap<String, u64> {
    let mut usage = HashMap::new();
    let Ok(mut entries) = tokio::fs::read_dir(buddy_files_dir).await else { return usage };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') || !entry.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        usage.insert(name, crate::repo::repo_size(&entry.path()).await);
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
/// opens one bidirectional stream per request (see protocol.rs),
/// potentially thousands of them over the lifetime of one connection (one
/// RepoWrite per pack in a backup), so this keeps accepting streams until
/// the peer closes the connection rather than handling just one and
/// returning.
///
/// Storage is scoped by sender: everything a given buddy sends us lives
/// under BUDDY_FILES_DIR/<their node id>/, and every request only ever
/// looks inside that one sender's own directory — a buddy can never see or
/// fetch what another buddy stored with us.
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
    // stream on it shares the same one.
    let quality = netinfo::connection_quality(&conn);

    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(_) => {
                // Peer closed the connection — normal end of a sync cycle.
                // Give stream tasks still writing their last pack a moment
                // to count it before the Activity summary goes out.
                let remote_id = remote_id.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    crate::activity::flush_incoming(&remote_id);
                });
                break;
            }
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
        SyncRequest::DiskStats => {
            handle_disk_stats(&mut send, &buddy_files_dir, &pledge_book).await?;
        }
        SyncRequest::RepoList { kind } => {
            crate::repo::handle_list(&mut send, &sender_dir, kind).await?;
        }
        SyncRequest::RepoRead { kind, id, offset, length } => {
            crate::repo::handle_read(
                &mut send,
                &sender_dir,
                &data_dir,
                &bandwidth_book,
                &quality,
                kind,
                id,
                offset,
                length,
            )
            .await?;
        }
        SyncRequest::RepoWrite { kind, id, len } => {
            crate::repo::handle_write(
                &mut send,
                &mut recv,
                &sender_dir,
                &remote_id,
                &pledge_book,
                &data_dir,
                &buddy_files_dir,
                &bandwidth_book,
                &quality,
                kind,
                id,
                len,
            )
            .await?;
        }
        SyncRequest::RepoRemove { kind, id } => {
            crate::repo::handle_remove(&mut send, &sender_dir, &remote_id, &pledge_book, &data_dir, kind, id).await?;
        }
    }

    send.stopped().await.ok();
    Ok(())
}

// Reject anything that would escape a base directory — an absolute path or
// any ".." component. Repository paths are built from checked ids already
// (repo.rs's rel_path), so this is a second guard on writes there; it's
// the main one for restores (chunked_restore.rs), which join paths read
// out of a snapshot under RESTORE_DIR.
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

/// Where an admitted write goes, and what it replaces (for undoing the
/// pledge reservation if it doesn't complete).
pub(crate) struct Admitted {
    pub(crate) dest: PathBuf,
    pub(crate) previous_size: u64,
}

/// The checks every write passes before a byte of it is read: path, real
/// disk space, then the pledge, which it also reserves (give it back with
/// `release_pledge` if the write doesn't complete).
pub(crate) async fn admit_put(
    sender_dir: &Path,
    remote_id: &str,
    pledge_book: &PledgeBook,
    buddy_files_dir: &Path,
    path: &str,
    ciphertext_len: u64,
) -> std::result::Result<Admitted, PutRejectReason> {
    let Some(dest) = safe_join(sender_dir, path) else {
        return Err(PutRejectReason::InvalidPath);
    };

    // A file already at this path (rustic writing the same id again after
    // a dropped connection) is replaced, so only the difference counts.
    let previous_size = tokio::fs::metadata(&dest).await.map(|m| m.len()).unwrap_or(0);
    let incoming_delta = ciphertext_len.saturating_sub(previous_size);

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
    let other_devices = received_by_other_devices(&book, remote_id);
    let state = book.entry(remote_id.to_string()).or_default();
    let projected = state.received_bytes.saturating_sub(previous_size).saturating_add(ciphertext_len);
    if other_devices.saturating_add(projected) > state.pledged_bytes {
        tracing::warn!(
            from = %remote_id,
            path = %path,
            attempted_bytes = ciphertext_len,
            pledged_bytes = state.pledged_bytes,
            received_bytes = state.received_bytes,
            other_devices_bytes = other_devices,
            "rejected file — would exceed this buddy's pledge"
        );
        return Err(PutRejectReason::PledgeExceeded);
    }
    state.received_bytes = projected;
    Ok(Admitted { dest, previous_size })
}

/// Undoes admit_put's pledge reservation for a write that didn't land.
pub(crate) fn release_pledge(pledge_book: &PledgeBook, remote_id: &str, ciphertext_len: u64, previous_size: u64) {
    let mut book = pledge_book.lock().unwrap();
    if let Some(state) = book.get_mut(remote_id) {
        state.received_bytes = state.received_bytes.saturating_sub(ciphertext_len).saturating_add(previous_size);
    }
}

// Every early-rejection branch decides *before* reading the incoming
// file body off `recv` — deliberately, so we don't waste time and
// bandwidth downloading megabytes of a pack we're about to throw away.
// But the sender (repo.rs's write) writes its entire body before it ever
// tries to read our ack, so if we just write the rejection ack without
// doing anything about the body they're still sending, their `write_all`
// blocks forever waiting for QUIC flow-control credit we'll never grant
// (we're not reading), while we sit in handle_stream's
// `send.stopped().await` waiting for them to finish sending — a real
// deadlock, not just a slow cycle. `RecvStream::stop()` sends a QUIC
// STOP_SENDING frame, which makes their blocked write fail immediately
// instead of hanging, so they can report the failure. The error code it
// carries is `reason`'s own code (see PutRejectReason), so the
// sender — which generally never gets to read the string ack below, since
// it's usually still mid-write when the stop lands — can still learn
// *why*, not just that it failed.
pub(crate) async fn reject_without_reading_body(
    recv: &mut iroh::endpoint::RecvStream,
    send: &mut iroh::endpoint::SendStream,
    reason: PutRejectReason,
) -> Result<()> {
    recv.stop(iroh::endpoint::VarInt::from_u32(reason.code())).ok();
    protocol::write_frame(send, &SyncAck::err(reason.message())).await
}

// Writes in progress live here, inside the sender's own folder: same
// filesystem as the final location (so moving into place is an atomic
// rename). Leftovers from an interrupted write are cleared at startup
// (clear_incoming).
const INCOMING_DIR: &str = ".incoming";
const IO_CHUNK: usize = 256 * 1024;

pub(crate) async fn incoming_tmp_path(sender_dir: &Path) -> Result<PathBuf> {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = sender_dir.join(INCOMING_DIR);
    tokio::fs::create_dir_all(&dir).await.context("failed to create upload staging folder")?;
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(dir.join(format!("{}-{n}.part", std::process::id())))
}

/// Reads exactly `len` bytes from `recv` into a new file at `path`,
/// returning their SHA-256. Flushed to disk before returning, so a file
/// isn't acknowledged until it's actually stored.
pub(crate) async fn receive_body(recv: &mut iroh::endpoint::RecvStream, path: &Path, len: u64) -> Result<String> {
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

/// Removes leftovers of writes interrupted by a restart or crash.
pub async fn clear_incoming(buddy_files_dir: &Path) {
    let Ok(mut entries) = tokio::fs::read_dir(buddy_files_dir).await else { return };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let _ = tokio::fs::remove_dir_all(entry.path().join(INCOMING_DIR)).await;
    }
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
    let pledged_out_total_bytes: u64 = pledged_out_total(&pledge_book.lock().unwrap());

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn former_buddy_devices_are_removed_after_30_days_unless_they_return() {
        let root = std::env::temp_dir().join(format!("bb-orphans-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (data, files) = (root.join("config"), root.join("buddy-files"));
        std::fs::create_dir_all(&data).unwrap();
        for dir in ["paired", "gone", "back"] {
            std::fs::create_dir_all(files.join(dir).join(".repo")).unwrap();
            std::fs::write(files.join(dir).join(".repo/config"), b"12345").unwrap();
        }
        std::fs::write(files.join(".backup-buddies-id"), b"marker").unwrap();
        let day = 24 * 60 * 60;
        let paired: std::collections::HashSet<String> = ["paired".to_string()].into();

        // First noticed: marked, nothing removed.
        assert!(sweep_orphans(&data, &files, &paired, 1000 * day).await.is_empty());
        assert_eq!(load_orphans(&data).keys().len(), 2);
        // A device that comes back is unmarked.
        let with_back: std::collections::HashSet<String> = ["paired".into(), "back".into()].into();
        assert!(sweep_orphans(&data, &files, &with_back, 1010 * day).await.is_empty());
        assert_eq!(load_orphans(&data).keys().collect::<Vec<_>>(), ["gone"]);
        // 30 days after it was first noticed, the other one goes.
        let removed = sweep_orphans(&data, &files, &with_back, 1030 * day).await;
        assert_eq!(removed, [("gone".to_string(), 5)]);
        assert!(!files.join("gone").exists() && files.join("paired").exists() && files.join("back").exists());
        assert!(files.join(".backup-buddies-id").exists(), "the folder's own marker isn't a buddy");
        assert!(load_orphans(&data).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    // The startup correction for a drifted usage ledger: only the
    // repository counts — not half-received writes, anything else in the
    // sender's folder, or the folder marker at the top of BUDDY_FILES_DIR.
    #[tokio::test]
    async fn usage_from_disk_counts_only_the_repository() {
        let root = std::env::temp_dir().join(format!("bb-usage-from-disk-test-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&root).await;
        let sender = root.join("buddyA");
        tokio::fs::create_dir_all(sender.join(".repo/data/ab")).await.unwrap();
        tokio::fs::create_dir_all(sender.join(INCOMING_DIR)).await.unwrap();
        tokio::fs::create_dir_all(root.join("buddyB")).await.unwrap();
        tokio::fs::write(root.join(".backup-buddies-id"), b"marker").await.unwrap();
        tokio::fs::write(sender.join(".repo/config"), vec![0u8; 10]).await.unwrap();
        tokio::fs::write(sender.join(".repo/data/ab/pack"), vec![0u8; 20]).await.unwrap();
        tokio::fs::write(sender.join("left-over.txt"), vec![0u8; 500]).await.unwrap();
        tokio::fs::write(sender.join(INCOMING_DIR).join("partial"), vec![0u8; 700]).await.unwrap();

        let usage = usage_from_disk(&root).await;
        assert_eq!(usage.get("buddyA"), Some(&30));
        assert_eq!(usage.get("buddyB"), Some(&0));
        assert_eq!(usage.len(), 2);

        clear_incoming(&root).await;
        assert!(!sender.join(INCOMING_DIR).exists(), "interrupted writes are cleared at startup");
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    // A pledge covers a buddy's whole account: three devices on a 1000-byte
    // pairing share 1000 bytes between them, not 1000 each.
    #[tokio::test]
    async fn pledge_is_shared_across_a_buddys_devices() {
        let root = std::env::temp_dir().join(format!("bb-pledge-test-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&root).await;
        std::fs::create_dir_all(&root).unwrap();
        let state = |account: &str| PledgeState { pledged_bytes: 1000, received_bytes: 0, account_id: Some(account.into()) };
        let book: PledgeBook = Arc::new(Mutex::new(HashMap::from([
            ("dev1".to_string(), state("acct-a")),
            ("dev2".to_string(), state("acct-a")),
            ("dev3".to_string(), state("acct-a")),
            ("other".to_string(), state("acct-b")),
        ])));
        let put = |dev: &'static str, path: &'static str, len: u64| {
            let (root, book) = (root.clone(), book.clone());
            async move { admit_put(&root.join(dev), dev, &book, &root, path, len).await.map(|_| ()) }
        };

        assert!(put("dev1", "a", 600).await.is_ok());
        assert!(put("dev2", "b", 400).await.is_ok(), "the rest of the pledge, from another device");
        assert!(matches!(put("dev3", "c", 1).await, Err(PutRejectReason::PledgeExceeded)));
        assert!(matches!(put("dev1", "d", 1).await, Err(PutRejectReason::PledgeExceeded)));
        assert!(put("other", "e", 1000).await.is_ok(), "another account has its own pledge");

        let snapshot = book.lock().unwrap().clone();
        assert_eq!(account_received_bytes(&snapshot, "dev3"), 1000);
        assert_eq!(account_received_bytes(&snapshot, "other"), 1000);
        assert_eq!(pledged_out_total(&snapshot), 2000, "each account's pledge counted once");

        // A device whose account isn't known yet (before the first poll)
        // only counts its own files.
        book.lock().unwrap().get_mut("dev3").unwrap().account_id = None;
        assert!(put("dev3", "c", 1).await.is_ok());
        let _ = tokio::fs::remove_dir_all(&root).await;
    }
}
