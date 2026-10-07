// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

use std::path::Path;
use std::sync::{Arc, Mutex};

use age::secrecy::SecretString;
use anyhow::{Context, Result};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl};
use serde::Serialize;

use crate::netinfo::{self, ConnectionQuality};
use crate::protocol::{
    self, DiskStatsResponse, ListEntry, ListResponse, ListVersionsResponse, SyncAck, SyncRequest,
    VersionEntry,
};
use crate::receive::safe_join;


/// Live progress for one in-flight multi-file restore, polled by the
/// dashboard (GET /api/buddies/:id/restore-progress) while the restore's
/// own POST is still in flight — the two are separate requests so a slow
/// restore doesn't leave the browser with nothing to show but a frozen
/// "Restoring…" for however long it takes. `total_files`/`total_bytes`
/// are set once up front by whoever creates the handle (they come from a
/// List call, not from here); this module only ever advances
/// `completed_files`/`bytes_done`/`current_path` as it goes, and never
/// touches `done`/`error` — the caller sets those once the restore this
/// handle belongs to actually finishes, success or not.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RestoreProgress {
    pub total_files: usize,
    pub completed_files: usize,
    pub total_bytes: u64,
    pub bytes_done: u64,
    pub current_path: Option<String>,
    pub started_unix: u64,
    pub done: bool,
    pub error: Option<String>,
}

pub type ProgressHandle = Arc<Mutex<RestoreProgress>>;

/// What one restore actually did, including transfer metrics — mirrors
/// backup.rs's BackupCycleStats so the dashboard can show both directions
/// the same way. bytes_restored sums each file's *ciphertext* length (the
/// decrypted plaintext is what lands on disk, but ciphertext is what
/// crossed the network, which is what a transfer rate should be measured
/// against).
#[derive(Debug, Clone, Copy, Default)]
pub struct RestoreStats {
    pub files_restored: usize,
    pub bytes_restored: u64,
    pub duration_ms: u64,
    pub connection: Option<ConnectionQuality>,
    // Bytes received, split by path (see netinfo::PathMeter).
    pub traffic: Option<netinfo::ByteSplit>,
}

/// Connects to a buddy and asks what they're holding for us — no
/// decryption, no writing to disk, just the file list (path + ciphertext
/// size). Used by the dashboard's file browser to show what's available
/// before the person picks what to restore, and by `run_restore` below to
/// get the full list it then restores everything from.
pub async fn list_buddy_files(
    endpoint: &Endpoint,
    relay_url: &RelayUrl,
    buddy_id: EndpointId,
) -> Result<Vec<ListEntry>> {
    let conn = connect(endpoint, relay_url, buddy_id).await?;
    list_on(&conn).await
}

/// Connects to a buddy and asks for their real disk numbers (see
/// DiskStatsResponse), plus our own local read on the quality of that
/// connection (direct vs. relayed, round-trip latency) — used by the
/// dashboard to show what a buddy actually has available, next to what
/// they've pledged, so an over-pledged or nearly-full buddy is visible
/// without either side having to ask the other directly.
pub async fn fetch_buddy_disk_stats(
    endpoint: &Endpoint,
    relay_url: &RelayUrl,
    buddy_id: EndpointId,
) -> Result<(DiskStatsResponse, ConnectionQuality)> {
    let conn = connect(endpoint, relay_url, buddy_id).await?;
    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;
    protocol::write_frame(&mut send, &SyncRequest::DiskStats).await?;
    send.finish().context("failed to finish send stream")?;
    let stats: DiskStatsResponse =
        protocol::read_frame(&mut recv).await.context("failed to read disk stats")?;
    Ok((stats, netinfo::connection_quality(&conn)))
}

/// Asks a buddy what backup slots still exist for one path — the file
/// browser's "History" affordance uses this to show what's recoverable
/// before the person picks a version to restore.
pub async fn list_file_versions(
    endpoint: &Endpoint,
    relay_url: &RelayUrl,
    buddy_id: EndpointId,
    path: &str,
) -> Result<Vec<VersionEntry>> {
    let conn = connect(endpoint, relay_url, buddy_id).await?;
    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;
    protocol::write_frame(&mut send, &SyncRequest::ListVersions { path: path.to_string() }).await?;
    send.finish().context("failed to finish send stream")?;
    let resp: ListVersionsResponse =
        protocol::read_frame(&mut recv).await.context("failed to read version list")?;
    Ok(resp.versions)
}

/// Restores one specific backup slot of one file — not the live copy.
/// Written alongside the live path with a suffix (`<path>.v<N>.bak`) so it
/// never clobbers a normal restore of the same file.
pub async fn restore_version(
    endpoint: &Endpoint,
    relay_url: &RelayUrl,
    _passphrase: &SecretString,
    buddy_id: EndpointId,
    restore_dir: &Path,
    path: &str,
    version: u32,
) -> Result<RestoreStats> {
    let started = std::time::Instant::now();
    let conn = connect(endpoint, relay_url, buddy_id).await?;
    let meter = netinfo::PathMeter::start(&conn, netinfo::Direction::Received);

    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;
    protocol::write_frame(&mut send, &SyncRequest::GetVersion { path: path.to_string(), version }).await?;
    send.finish().context("failed to finish send stream")?;

    let ack: SyncAck = protocol::read_frame(&mut recv).await.context("failed to read ack")?;
    if !ack.ok {
        anyhow::bail!("buddy could not serve that version: {}", ack.error.unwrap_or_default());
    }
    let suffixed = format!("{path}.v{version}.bak");
    let Some(dest) = safe_join(restore_dir, &suffixed) else {
        anyhow::bail!("buddy sent an unsafe path: {path:?}");
    };
    let ciphertext_len = receive_and_decrypt(&mut recv, dest, None).await?;

    Ok(RestoreStats {
        files_restored: 1,
        bytes_restored: ciphertext_len,
        duration_ms: started.elapsed().as_millis() as u64,
        connection: Some(netinfo::connection_quality(&conn)),
        traffic: Some(meter.finish(&conn)),
    })
}

/// Asks a buddy to remove, for good, the backup copies it keeps of a file
/// we deleted (dashboard's "Delete permanently"). Needs the buddy on 0.9.0+.
pub async fn purge_deleted(
    endpoint: &Endpoint,
    relay_url: &RelayUrl,
    buddy_id: EndpointId,
    path: &str,
) -> Result<()> {
    let conn = connect(endpoint, relay_url, buddy_id).await?;
    if crate::backup::buddy_protocol_version(&conn).await < 4 {
        anyhow::bail!("your buddy's client is too old for this — it'll work once they update (the copies are removed after 30 days anyway)");
    }
    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;
    protocol::write_frame(&mut send, &SyncRequest::PurgeDeleted { path: path.to_string() }).await?;
    send.finish().context("failed to finish send stream")?;
    let ack: SyncAck = protocol::read_frame(&mut recv).await.context("failed to read buddy's reply")?;
    if !ack.ok {
        anyhow::bail!("{}", ack.error.unwrap_or_else(|| "buddy refused".to_string()));
    }
    Ok(())
}

async fn connect(
    endpoint: &Endpoint,
    relay_url: &RelayUrl,
    buddy_id: EndpointId,
) -> Result<iroh::endpoint::Connection> {
    let addr = EndpointAddr::new(buddy_id).with_relay_url(relay_url.clone());
    endpoint.connect(addr, protocol::ALPN).await.map_err(protocol::explain_connect_error)
}

/// Streams a file's ciphertext from `recv` (after its ok ack) through
/// decryption into `dest`, in bounded memory. `dest` only appears once the
/// whole file decrypted and authenticated. Returns the encrypted bytes
/// received. With `progress`, adds to `bytes_done` as bytes arrive, so a big
/// file shows movement rather than sitting still until it's done.
async fn receive_and_decrypt(
    recv: &mut iroh::endpoint::RecvStream,
    dest: std::path::PathBuf,
    progress: Option<&ProgressHandle>,
) -> Result<u64> {
    let (tx, done) = crate::crypto::decrypt_to_file(dest);
    let mut buf = vec![0u8; crate::crypto::PIPE_CHUNK];
    let mut total = 0u64;
    let mut read_err = None;
    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                total += n as u64;
                if let Some(p) = progress
                    && let Ok(mut g) = p.lock()
                {
                    g.bytes_done += n as u64;
                }
                // Decryption stopped early (bad data / wrong passphrase):
                // its own error, returned below, says why.
                if tx.send(Ok(buf[..n].to_vec())).await.is_err() {
                    break;
                }
            }
            Ok(None) => break,
            Err(err) => {
                let _ = tx.send(Err(std::io::Error::other("connection ended mid-file"))).await;
                read_err = Some(err);
                break;
            }
        }
    }
    drop(tx);
    let decrypted = done.await.context("decryption task failed")?;
    if let Some(err) = read_err {
        return Err(err).context("failed to read file bytes");
    }
    decrypted?;
    Ok(total)
}

async fn list_on(conn: &iroh::endpoint::Connection) -> Result<Vec<ListEntry>> {
    // Chunked list first (any number of files); an older buddy drops that
    // request, and then the single-frame List is all it supports.
    if let Ok(files) = list_stream_on(conn).await {
        return Ok(files);
    }
    list_single_on(conn).await
}

async fn list_stream_on(conn: &iroh::endpoint::Connection) -> Result<Vec<ListEntry>> {
    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;
    protocol::write_frame(&mut send, &SyncRequest::ListStream).await?;
    send.finish().context("failed to finish send stream")?;
    let mut files = Vec::new();
    loop {
        let chunk: protocol::ListChunk = protocol::read_frame(&mut recv).await.context("failed to read file list")?;
        files.extend(chunk.files);
        if chunk.done {
            return Ok(files);
        }
    }
}

async fn list_single_on(conn: &iroh::endpoint::Connection) -> Result<Vec<ListEntry>> {
    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;
    protocol::write_frame(&mut send, &SyncRequest::List).await?;
    send.finish().context("failed to finish send stream")?;
    let resp: ListResponse =
        protocol::read_frame(&mut recv).await.context("failed to read file list")?;
    Ok(resp.files)
}

/// Pulls everything a buddy is holding for us back down, decrypts it with
/// our own passphrase, and writes it under `restore_dir` (mirroring the
/// relative paths it was backed up with). Meant for manual, one-shot use —
/// the `restore` CLI subcommand, or the dashboard's "Restore everything"
/// button.
pub async fn run_restore(
    endpoint: &Endpoint,
    relay_url: &RelayUrl,
    _passphrase: &SecretString,
    buddy_id: EndpointId,
    restore_dir: &Path,
) -> Result<RestoreStats> {
    let started = std::time::Instant::now();
    let conn = connect(endpoint, relay_url, buddy_id).await?;
    let meter = netinfo::PathMeter::start(&conn, netinfo::Direction::Received);
    let files = list_on(&conn).await?;
    tracing::info!(count = files.len(), "buddy reports this many files on restore");

    let paths: Vec<String> = files.into_iter().map(|f| f.path).collect();
    let (files_restored, bytes_restored) =
        restore_paths_on(&conn, _passphrase, restore_dir, &paths, None).await?;
    Ok(RestoreStats {
        files_restored,
        bytes_restored,
        duration_ms: started.elapsed().as_millis() as u64,
        connection: Some(netinfo::connection_quality(&conn)),
        traffic: Some(meter.finish(&conn)),
    })
}

/// Same as `run_restore`, but only the given paths (as returned by
/// `list_buddy_files`) rather than everything — what the dashboard uses
/// for every restore it kicks off (a plain "Restore", "Restore all",
/// "Restore selected", and a folder's "Restore" all resolve to a path
/// list before calling this, so a deleted-but-recoverable entry never
/// even gets attempted here — see the dashboard's restore_handler).
/// Connects once and restores every requested path over that one
/// connection rather than reconnecting per file. `progress`, if given,
/// is updated after each file so a poller elsewhere can show live
/// progress while this is still running — see `RestoreProgress`'s doc
/// comment for who owns which fields.
pub async fn restore_selected(
    endpoint: &Endpoint,
    relay_url: &RelayUrl,
    _passphrase: &SecretString,
    buddy_id: EndpointId,
    restore_dir: &Path,
    paths: &[String],
    progress: Option<ProgressHandle>,
) -> Result<RestoreStats> {
    let started = std::time::Instant::now();
    let conn = connect(endpoint, relay_url, buddy_id).await?;
    let meter = netinfo::PathMeter::start(&conn, netinfo::Direction::Received);
    let (files_restored, bytes_restored) =
        restore_paths_on(&conn, _passphrase, restore_dir, paths, progress.as_ref()).await?;
    Ok(RestoreStats {
        files_restored,
        bytes_restored,
        duration_ms: started.elapsed().as_millis() as u64,
        connection: Some(netinfo::connection_quality(&conn)),
        traffic: Some(meter.finish(&conn)),
    })
}

// Returns (files restored, total ciphertext bytes read) — the byte total
// is what a transfer rate should be computed against, same reasoning as
// backup.rs's put_one_file returning ciphertext size rather than
// plaintext size.
async fn restore_paths_on(
    conn: &iroh::endpoint::Connection,
    _passphrase: &SecretString,
    restore_dir: &Path,
    paths: &[String],
    progress: Option<&ProgressHandle>,
) -> Result<(usize, u64)> {
    let mut restored = 0;
    let mut attempted = 0;
    let mut bytes = 0u64;
    for rel_path in paths {
        if let Some(p) = progress
            && let Ok(mut g) = p.lock() {
                g.current_path = Some(rel_path.clone());
            }
        match restore_one_file(conn, restore_dir, rel_path, progress).await {
            Ok(ciphertext_len) => {
                restored += 1;
                bytes += ciphertext_len;
            }
            Err(err) => tracing::warn!(path = %rel_path, ?err, "failed to restore file"),
        }
        attempted += 1;
        // completed_files tracks files *attempted*, not just successes —
        // a failed file is still done being tried, and progress should
        // keep visibly moving rather than appear to stall on it.
        if let Some(p) = progress
            && let Ok(mut g) = p.lock() {
                g.completed_files = attempted;
                g.bytes_done = bytes;
                g.current_path = None;
            }
    }
    Ok((restored, bytes))
}

// Returns the ciphertext length read off the wire on success — see
// restore_paths_on's doc comment for why the caller wants that, not the
// decrypted plaintext length.
async fn restore_one_file(
    conn: &iroh::endpoint::Connection,
    restore_dir: &Path,
    rel_path: &str,
    progress: Option<&ProgressHandle>,
) -> Result<u64> {
    let Some(dest) = safe_join(restore_dir, rel_path) else {
        anyhow::bail!("buddy sent an unsafe path in its file list: {rel_path:?}");
    };
    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;
    protocol::write_frame(&mut send, &SyncRequest::Get { path: rel_path.to_string() }).await?;
    send.finish().context("failed to finish send stream")?;

    let ack: SyncAck = protocol::read_frame(&mut recv).await.context("failed to read ack")?;
    if !ack.ok {
        anyhow::bail!("buddy could not serve file: {}", ack.error.unwrap_or_default());
    }
    receive_and_decrypt(&mut recv, dest, progress).await
}
