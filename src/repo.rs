// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

//! Chunked backups, the buddy's side and the wire calls (protocol v5).
//!
//! Whole-file backups re-send a file in full whenever it changes, and a
//! rename or a move looks like a delete plus a new file: renaming four ISOs
//! on a test device re-sent ~15 GB. With chunked backups the sender keeps a
//! restic-format repository (built with rustic_core): files are split into
//! content-defined chunks, encrypted, deduplicated and packed into ~32 MB
//! pack files, so a rename costs nothing and an edit costs only the chunks
//! it touched. The buddy stores that repository under
//! `<buddy-files>/<sender>/.repo/` as opaque encrypted files, by kind and
//! id, and never sees file names, counts, sizes or folders at all.
//!
//! Every repository file but `config` is named by the SHA-256 of its
//! contents, so the buddy checks each write against its name. Repository
//! files count against the sender's pledge like any other stored bytes,
//! and the real-disk floor applies to them the same way.

use std::path::Path;

use anyhow::{Context, Result};

use crate::bandwidth::BandwidthBook;
use crate::netinfo::ConnectionQuality;
use crate::protocol::{
    self, PutRejectReason, RepoFileEntry, RepoFileKind, RepoListChunk, RepoReadReply, SyncAck, SyncRequest,
};
use crate::receive::{self, PledgeBook};

/// Where a sender's repository lives inside their folder. Hidden from the
/// whole-file listings (receive.rs's collect_files), like `.versions/`.
pub(crate) const REPO_DIR: &str = ".repo";

/// rustic_core states file sizes as u32, so no repository file is bigger.
const MAX_REPO_FILE_BYTES: u64 = u32::MAX as u64;

/// The id rustic gives the one `config` file (it has no content hash).
pub(crate) const CONFIG_ID: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const IO_CHUNK: usize = 256 * 1024;

fn valid_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// A repository file's path relative to the sender's folder, laid out like
/// restic's own (packs sharded by the first two hex digits, so no folder
/// holds tens of thousands of files). None for an id that isn't one.
fn rel_path(kind: RepoFileKind, id: &str) -> Option<String> {
    if kind == RepoFileKind::Config {
        return Some(format!("{REPO_DIR}/config"));
    }
    if !valid_id(id) {
        return None;
    }
    Some(match kind {
        RepoFileKind::Pack => format!("{REPO_DIR}/data/{}/{id}", &id[..2]),
        RepoFileKind::Index => format!("{REPO_DIR}/index/{id}"),
        RepoFileKind::Key => format!("{REPO_DIR}/keys/{id}"),
        RepoFileKind::Snapshot => format!("{REPO_DIR}/snapshots/{id}"),
        RepoFileKind::Config => unreachable!(),
    })
}

/// Total size of everything in a sender's repository. Counted against
/// their pledge (receive.rs's usage_from_disk), since all of it, old
/// snapshots included, is space this host is giving them.
pub(crate) async fn repo_size(sender_dir: &Path) -> u64 {
    let dir = sender_dir.join(REPO_DIR);
    tokio::task::spawn_blocking(move || {
        walkdir::WalkDir::new(dir)
            .into_iter()
            .flatten()
            .filter(|e| e.file_type().is_file())
            .filter_map(|e| e.metadata().ok())
            .map(|m| m.len())
            .sum()
    })
    .await
    .unwrap_or(0)
}

/// Every file of one kind, with its size. Only names that are real ids are
/// listed, so a stray file in the folder never reaches rustic.
async fn list_kind(sender_dir: &Path, kind: RepoFileKind) -> Vec<RepoFileEntry> {
    let repo = sender_dir.join(REPO_DIR);
    tokio::task::spawn_blocking(move || {
        let (dir, depth) = match kind {
            RepoFileKind::Config => {
                return std::fs::metadata(repo.join("config"))
                    .map(|m| vec![RepoFileEntry { id: CONFIG_ID.to_string(), size: m.len() }])
                    .unwrap_or_default();
            }
            RepoFileKind::Pack => (repo.join("data"), 2),
            RepoFileKind::Index => (repo.join("index"), 1),
            RepoFileKind::Key => (repo.join("keys"), 1),
            RepoFileKind::Snapshot => (repo.join("snapshots"), 1),
        };
        walkdir::WalkDir::new(dir)
            .min_depth(depth)
            .max_depth(depth)
            .into_iter()
            .flatten()
            .filter(|e| e.file_type().is_file())
            .filter_map(|e| {
                let id = e.file_name().to_str()?.to_string();
                let size = e.metadata().ok()?.len();
                valid_id(&id).then_some(RepoFileEntry { id, size })
            })
            .collect()
    })
    .await
    .unwrap_or_default()
}

// ---- The buddy's side ----

pub(crate) async fn handle_list(
    send: &mut iroh::endpoint::SendStream,
    sender_dir: &Path,
    kind: RepoFileKind,
) -> Result<()> {
    let files = list_kind(sender_dir, kind).await;
    let mut chunks = files.chunks(protocol::REPO_LIST_CHUNK_ENTRIES).peekable();
    if chunks.peek().is_none() {
        protocol::write_frame(send, &RepoListChunk { files: Vec::new(), done: true }).await?;
    }
    while let Some(chunk) = chunks.next() {
        let done = chunks.peek().is_none();
        let files = chunk.iter().map(|e| RepoFileEntry { id: e.id.clone(), size: e.size }).collect();
        protocol::write_frame(send, &RepoListChunk { files, done }).await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_read(
    send: &mut iroh::endpoint::SendStream,
    sender_dir: &Path,
    data_dir: &Path,
    bandwidth_book: &BandwidthBook,
    quality: &ConnectionQuality,
    kind: RepoFileKind,
    id: String,
    offset: u64,
    length: Option<u64>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let refuse = |error: &str| RepoReadReply { len: None, error: Some(error.to_string()) };
    let Some(path) = rel_path(kind, &id).map(|rel| sender_dir.join(rel)) else {
        return protocol::write_frame(send, &refuse("invalid id")).await;
    };
    let Ok(mut file) = tokio::fs::File::open(&path).await else {
        return protocol::write_frame(send, &refuse("not found")).await;
    };
    let size = file.metadata().await.context("failed to read stored file")?.len();
    let len = match length {
        Some(len) if offset.checked_add(len).is_some_and(|end| end <= size) => len,
        None if offset <= size => size - offset,
        _ => return protocol::write_frame(send, &refuse("range is past the end of the file")).await,
    };
    file.seek(std::io::SeekFrom::Start(offset)).await.context("failed to read stored file")?;
    protocol::write_frame(send, &RepoReadReply { len: Some(len), error: None }).await?;

    let mut buf = vec![0u8; IO_CHUNK];
    let mut remaining = len;
    while remaining > 0 {
        let n = remaining.min(IO_CHUNK as u64) as usize;
        file.read_exact(&mut buf[..n]).await.context("failed to read stored file")?;
        send.write_all(&buf[..n]).await.context("failed to send file bytes")?;
        remaining -= n as u64;
    }
    send.finish().context("failed to finish send stream")?;
    crate::bandwidth::record(data_dir, bandwidth_book, quality, len).await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_write(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    sender_dir: &Path,
    remote_id: &str,
    pledge_book: &PledgeBook,
    data_dir: &Path,
    buddy_files_dir: &Path,
    bandwidth_book: &BandwidthBook,
    quality: &ConnectionQuality,
    kind: RepoFileKind,
    id: String,
    len: u64,
) -> Result<()> {
    let Some(rel) = rel_path(kind, &id) else {
        return receive::reject_without_reading_body(recv, send, PutRejectReason::InvalidPath).await;
    };
    if len > MAX_REPO_FILE_BYTES {
        return receive::reject_without_reading_body(recv, send, PutRejectReason::TooLarge).await;
    }
    // The same size, disk-floor and pledge checks as a whole-file upload,
    // which also reserve the space (handed back below if this fails).
    let admitted =
        match receive::admit_put(sender_dir, remote_id, pledge_book, buddy_files_dir, &rel, len, 0).await {
            Ok(a) => a,
            Err(reason) => return receive::reject_without_reading_body(recv, send, reason).await,
        };
    let rollback = || receive::release_pledge(pledge_book, remote_id, len, admitted.previous_size);

    let tmp = match receive::incoming_tmp_path(sender_dir).await {
        Ok(tmp) => tmp,
        Err(err) => {
            rollback();
            return Err(err);
        }
    };
    let hash = match receive::receive_body(recv, &tmp, len).await {
        Ok(hash) => hash,
        Err(err) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            rollback();
            return Err(err).context("failed to read repository file bytes");
        }
    };
    // Content-addressed: a file whose bytes don't match its name was
    // damaged on the way (or isn't what the sender thinks it is).
    if kind != RepoFileKind::Config && hash != id {
        let _ = tokio::fs::remove_file(&tmp).await;
        rollback();
        return protocol::write_frame(send, &SyncAck::err("hash mismatch")).await;
    }

    // No backup copies here, unlike whole files: the repository keeps its
    // own history (snapshots), and a rewrite of the same id is the same
    // bytes, except for `config`, which the sender only writes when it
    // creates the repository.
    let stored = async {
        if let Some(parent) = admitted.dest.parent() {
            tokio::fs::create_dir_all(parent).await.context("failed to create repository folder")?;
        }
        tokio::fs::rename(&tmp, &admitted.dest).await.context("failed to store repository file")
    }
    .await;
    if let Err(err) = stored {
        let _ = tokio::fs::remove_file(&tmp).await;
        rollback();
        return Err(err);
    }

    if let Err(err) = receive::save_usage_ledger(data_dir, pledge_book).await {
        tracing::warn!(?err, "failed to persist usage ledger");
    }
    crate::bandwidth::record(data_dir, bandwidth_book, quality, len).await;
    protocol::write_frame(send, &SyncAck::ok()).await?;
    tracing::debug!(from = %remote_id, ?kind, %id, bytes = len, "stored repository file from buddy");
    Ok(())
}

pub(crate) async fn handle_remove(
    send: &mut iroh::endpoint::SendStream,
    sender_dir: &Path,
    remote_id: &str,
    pledge_book: &PledgeBook,
    data_dir: &Path,
    kind: RepoFileKind,
    id: String,
) -> Result<()> {
    let Some(path) = rel_path(kind, &id).map(|rel| sender_dir.join(rel)) else {
        return protocol::write_frame(send, &SyncAck::err("invalid id")).await;
    };
    let freed = tokio::fs::metadata(&path).await.map(|m| m.len()).unwrap_or(0);
    match tokio::fs::remove_file(&path).await {
        Ok(()) => {}
        // Idempotent: already gone is fine (a prune retried after a drop).
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return protocol::write_frame(send, &SyncAck::err(format!("failed to remove: {err}"))).await,
    }
    if freed > 0 {
        {
            let mut book = pledge_book.lock().unwrap();
            if let Some(state) = book.get_mut(remote_id) {
                state.received_bytes = state.received_bytes.saturating_sub(freed);
            }
        }
        if let Err(err) = receive::save_usage_ledger(data_dir, pledge_book).await {
            tracing::warn!(?err, "failed to persist usage ledger after a repository remove");
        }
    }
    protocol::write_frame(send, &SyncAck::ok()).await?;
    tracing::debug!(from = %remote_id, ?kind, %id, "removed repository file for buddy");
    Ok(())
}

// ---- The sender's side (called by repo_backend.rs) ----

/// Lists one kind of file in our repository on the buddy.
pub(crate) async fn list(conn: &iroh::endpoint::Connection, kind: RepoFileKind) -> Result<Vec<RepoFileEntry>> {
    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;
    protocol::write_frame(&mut send, &SyncRequest::RepoList { kind }).await?;
    send.finish()?;
    let mut files = Vec::new();
    loop {
        let chunk: RepoListChunk = protocol::read_frame(&mut recv).await.context("failed to read repository list")?;
        files.extend(chunk.files);
        if chunk.done {
            return Ok(files);
        }
    }
}

/// Reads part of a repository file (the rest of it when `length` is None).
pub(crate) async fn read(
    conn: &iroh::endpoint::Connection,
    kind: RepoFileKind,
    id: &str,
    offset: u64,
    length: Option<u64>,
) -> Result<Vec<u8>> {
    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;
    protocol::write_frame(&mut send, &SyncRequest::RepoRead { kind, id: id.to_string(), offset, length }).await?;
    send.finish()?;
    let reply: RepoReadReply = protocol::read_frame(&mut recv).await.context("failed to read reply")?;
    let Some(len) = reply.len else {
        anyhow::bail!("buddy couldn't read {kind:?} {id}: {}", reply.error.unwrap_or_default());
    };
    if len > MAX_REPO_FILE_BYTES {
        anyhow::bail!("buddy announced {len} bytes for {kind:?} {id}, more than any repository file");
    }
    let mut data = vec![0u8; len as usize];
    recv.read_exact(&mut data).await.context("connection ended mid-file")?;
    Ok(data)
}

/// Stores a repository file. A refusal (pledge or disk full) fails with the
/// same STOP_SENDING reason a whole-file upload gets.
pub(crate) async fn write(conn: &iroh::endpoint::Connection, kind: RepoFileKind, id: &str, data: &[u8]) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;
    protocol::write_frame(&mut send, &SyncRequest::RepoWrite { kind, id: id.to_string(), len: data.len() as u64 })
        .await?;
    for chunk in data.chunks(IO_CHUNK) {
        send.write_all(chunk).await.context("failed to send repository file")?;
    }
    send.finish().context("failed to finish send stream")?;
    let ack: SyncAck = protocol::read_frame(&mut recv).await.context("failed to read ack")?;
    if !ack.ok {
        anyhow::bail!("buddy refused {kind:?} {id}: {}", ack.error.unwrap_or_default());
    }
    Ok(())
}

/// Removes a repository file (fine if it's already gone).
pub(crate) async fn remove(conn: &iroh::endpoint::Connection, kind: RepoFileKind, id: &str) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;
    protocol::write_frame(&mut send, &SyncRequest::RepoRemove { kind, id: id.to_string() }).await?;
    send.finish()?;
    let ack: SyncAck = protocol::read_frame(&mut recv).await.context("failed to read ack")?;
    if !ack.ok {
        anyhow::bail!("buddy couldn't remove {kind:?} {id}: {}", ack.error.unwrap_or_default());
    }
    Ok(())
}

/// The repository folder for one sender, for the buddy's own housekeeping.
#[cfg(test)]
pub(crate) fn repo_dir(sender_dir: &Path) -> std::path::PathBuf {
    sender_dir.join(REPO_DIR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_stay_inside_the_repository() {
        let id = "ab".repeat(32);
        assert_eq!(rel_path(RepoFileKind::Pack, &id).unwrap(), format!(".repo/data/ab/{id}"));
        assert_eq!(rel_path(RepoFileKind::Snapshot, &id).unwrap(), format!(".repo/snapshots/{id}"));
        assert_eq!(rel_path(RepoFileKind::Config, "anything").unwrap(), ".repo/config");
        // Anything that isn't 64 lowercase hex digits is refused, so no id
        // can climb out of the folder or name another file.
        for bad in ["../../etc/passwd", "", &"AB".repeat(32), &"ab".repeat(33), &format!("{}/x", "ab".repeat(31))] {
            assert!(rel_path(RepoFileKind::Pack, bad).is_none(), "{bad}");
        }
    }
}
