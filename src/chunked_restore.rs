// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

//! Browse files, History and restores for a chunked backup (chunked.rs),
//! answering in the same shapes as whole-file ones (restore.rs), so the
//! dashboard doesn't need to know which kind a buddy has.
//!
//! - Files: the latest snapshot. A file missing from it but present in any
//!   older one is listed as deleted, like a whole file that only survives
//!   as backup copies (so after a rename, the old name is still there to
//!   restore from).
//! - History: the file's distinct earlier contents across all snapshots,
//!   newest first, so hourly and daily restore points instead of the two
//!   copies a whole file keeps.
//! - Restores don't use rustic's own restore: in a spike it read on 20
//!   threads with no backpressure (1.9 GB of memory restoring 1.9 GB) and
//!   unwraps every read, so one failed network read would crash the
//!   client. Each file is read in 4 MiB pieces into a temporary file and
//!   moved into place once complete (~250 MB peak in the same spike).

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl};
use rustic_core::repofile::{Node, SnapshotFile};
use rustic_core::{Credentials, IndexedFullStatus, LsOptions, ReadBackend, Repository, RepositoryBackends, TreeId};

use crate::netinfo;
use crate::protocol::{self, VersionEntry};
use crate::receive::safe_join;
use crate::repo_backend::BuddyBackend;
use crate::restore::{BuddyFile, ProgressHandle, RestoreStats};

const READ_PIECE: usize = 4 * 1024 * 1024;

/// Backup copies of a whole file go after 30 days; old snapshots age out
/// on the same schedule (chunked.rs's retention), so History says so too.
const KEPT_SECS: u64 = 30 * 24 * 60 * 60;

/// One pack file as the buddy stores it, for "What your buddy sees".
#[derive(Debug, Clone, serde::Serialize)]
pub struct StoredPack {
    /// Its path in the buddy's `.repo/` folder, also what /peek takes.
    pub remote: String,
    pub size: u64,
}

pub struct Listing {
    pub files: Vec<BuddyFile>,
    pub packs: Vec<StoredPack>,
}

type Repo = Repository<IndexedFullStatus>;

/// A connection to the buddy and a backend that uses it, plus a meter on
/// it for the bandwidth totals.
async fn connect(
    endpoint: &Endpoint,
    relay_url: &RelayUrl,
    buddy_id: EndpointId,
) -> Result<(iroh::endpoint::Connection, Arc<BuddyBackend>)> {
    let addr = EndpointAddr::new(buddy_id).with_relay_url(relay_url.clone());
    let conn = endpoint.connect(addr, protocol::ALPN).await.map_err(protocol::explain_connect_error)?;
    let backend = Arc::new(BuddyBackend::new(endpoint.clone(), relay_url.clone(), buddy_id, Some(conn.clone())));
    Ok((conn, backend))
}

fn open(backend: Arc<BuddyBackend>) -> Result<Repo> {
    let backends = RepositoryBackends::new(backend, None);
    let repo = Repository::new(&crate::chunked::repo_options(), &backends)?
        .open(&Credentials::Masterkey(crate::chunked::master_key()))?
        .to_indexed()?;
    Ok(repo)
}

/// Snapshots, newest first.
fn snapshots(repo: &Repo) -> Result<Vec<SnapshotFile>> {
    let mut snaps = repo.get_all_snapshots()?;
    snaps.sort_by_key(|s| std::cmp::Reverse(s.time.timestamp()));
    Ok(snaps)
}

/// The backup folder's path inside a snapshot (the container's
/// BACKUP_DIR, e.g. `/backup`).
fn root_of(snap: &SnapshotFile) -> String {
    snap.paths.iter().next().map(|p| p.to_string()).unwrap_or_else(|| "/".to_string())
}

/// Every file in a snapshot, by its path relative to the backup folder.
fn files_in(repo: &Repo, snap: &SnapshotFile) -> Result<HashMap<String, Node>> {
    let root = repo.node_from_snapshot_path(&format!("{}:{}", snap.id, root_of(snap)), |_| true)?;
    let mut files = HashMap::new();
    for item in repo.ls(&root, &LsOptions::default())? {
        let (path, node) = item?;
        if node.is_file() {
            files.insert(path.to_string_lossy().replace('\\', "/"), node);
        }
    }
    Ok(files)
}

/// The tree of the backup folder in a snapshot.
fn root_tree(repo: &Repo, snap: &SnapshotFile) -> Option<TreeId> {
    repo.node_from_snapshot_path(&format!("{}:{}", snap.id, root_of(snap)), |_| true).ok()?.subtree
}

/// Adds every file under `old` that isn't under `new` (by the same path) to
/// `out`, with its size. Folders whose trees are identical are skipped.
fn missing_from(
    repo: &Repo,
    old: TreeId,
    new: Option<TreeId>,
    prefix: &str,
    out: &mut HashMap<String, u64>,
) -> Result<()> {
    if Some(old) == new {
        return Ok(());
    }
    let new_nodes: HashMap<_, Node> = match new {
        Some(id) => repo.get_tree(&id)?.nodes.into_iter().map(|n| (n.name().into_owned(), n)).collect(),
        None => HashMap::new(),
    };
    for node in repo.get_tree(&old)?.nodes {
        let name = node.name().into_owned();
        let path = if prefix.is_empty() {
            name.to_string_lossy().into_owned()
        } else {
            format!("{prefix}/{}", name.to_string_lossy())
        };
        let counterpart = new_nodes.get(&name);
        if node.is_dir() {
            if let Some(subtree) = node.subtree {
                let new_sub = counterpart.filter(|n| n.is_dir()).and_then(|n| n.subtree);
                missing_from(repo, subtree, new_sub, &path, out)?;
            }
        } else if node.is_file() && !counterpart.is_some_and(Node::is_file) {
            out.entry(path).or_insert(node.meta.size);
        }
    }
    Ok(())
}

/// One file's node in a snapshot, if it's there.
fn file_in(repo: &Repo, snap: &SnapshotFile, path: &str) -> Option<Node> {
    let full = format!("{}:{}/{}", snap.id, root_of(snap).trim_end_matches('/'), path);
    repo.node_from_snapshot_path(&full, |_| true).ok().filter(Node::is_file)
}

fn unix(snap: &SnapshotFile) -> u64 {
    u64::try_from(snap.time.timestamp().as_second()).unwrap_or(0)
}

pub async fn list(endpoint: &Endpoint, relay_url: &RelayUrl, buddy_id: EndpointId) -> Result<Listing> {
    let (conn, backend) = connect(endpoint, relay_url, buddy_id).await?;
    let job = {
        let backend = backend.clone();
        tokio::task::spawn_blocking(move || -> Result<Listing> {
            let packs = backend
                .list_with_size(rustic_core::FileType::Pack)?
                .into_iter()
                .map(|(id, size)| {
                    let id = id.to_hex().to_string();
                    StoredPack { remote: format!("data/{}/{id}", &id[..2]), size: size.into() }
                })
                .collect();
            let repo = open(backend)?;
            let snaps = snapshots(&repo)?;
            let Some(latest) = snaps.first() else {
                return Ok(Listing { files: Vec::new(), packs });
            };
            let live = files_in(&repo, latest)?;
            // Deleted files: in an older snapshot but not the latest, found
            // by comparing each older snapshot's tree with the latest's.
            // An unchanged folder has the same tree id in both and is
            // skipped without being read, so this costs what changed, not
            // the number of files, even across thousands of snapshots.
            let latest_root = root_tree(&repo, latest);
            let mut seen_roots = HashSet::new();
            let mut deleted: HashMap<String, u64> = HashMap::new();
            for snap in &snaps[1..] {
                let Some(root) = root_tree(&repo, snap) else { continue };
                if seen_roots.insert(root) {
                    missing_from(&repo, root, latest_root, "", &mut deleted)?;
                }
            }
            let mut files: Vec<BuddyFile> = live
                .into_iter()
                .map(|(path, node)| BuddyFile { path, size: node.meta.size, deleted: false, remote: String::new() })
                .chain(deleted.into_iter().map(|(path, size)| BuddyFile { path, size, deleted: true, remote: String::new() }))
                .collect();
            files.sort_by(|a, b| a.path.cmp(&b.path));
            Ok(Listing { files, packs })
        })
    };
    let result = job.await.context("listing task failed")?;
    backend.close();
    conn.close(0u32.into(), b"done");
    result
}

/// A file's distinct earlier contents, newest first: (snapshot, node). The
/// latest snapshot's own copy isn't one (it's the live file), unless the
/// file was deleted since.
fn versions_of(repo: &Repo, snaps: &[SnapshotFile], path: &str) -> Vec<(SnapshotFile, Node)> {
    let current = snaps.first().and_then(|s| file_in(repo, s, path)).and_then(|n| n.content);
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for snap in snaps {
        let Some(node) = file_in(repo, snap, path) else { continue };
        let Some(content) = node.content.clone() else { continue };
        if Some(&content) == current.as_ref() || !seen.insert(content) {
            continue;
        }
        out.push((snap.clone(), node));
    }
    out
}

pub async fn list_versions(
    endpoint: &Endpoint,
    relay_url: &RelayUrl,
    buddy_id: EndpointId,
    path: &str,
) -> Result<Vec<VersionEntry>> {
    let (conn, backend) = connect(endpoint, relay_url, buddy_id).await?;
    let path = path.to_string();
    let job = {
        let backend = backend.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<VersionEntry>> {
            let repo = open(backend)?;
            let snaps = snapshots(&repo)?;
            Ok(versions_of(&repo, &snaps, &path)
                .into_iter()
                .enumerate()
                .map(|(i, (snap, node))| VersionEntry {
                    version: i as u32 + 1,
                    size: node.meta.size,
                    modified_unix: Some(unix(&snap)),
                    expires_unix: Some(unix(&snap) + KEPT_SECS),
                })
                .collect())
        })
    };
    let result = job.await.context("history task failed")?;
    backend.close();
    conn.close(0u32.into(), b"done");
    result
}

/// Writes one file from the repository to `dest`, in READ_PIECE reads; it
/// only appears there once complete. Returns its size.
fn restore_node(repo: &Repo, node: &Node, dest: &Path, progress: Option<&ProgressHandle>) -> Result<u64> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).context("failed to create restore directory")?;
    }
    let name = dest.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = dest.with_file_name(format!(".{name}.restoring-{}", std::process::id()));
    let written = (|| -> Result<u64> {
        let open = repo.open_file(node)?;
        let size = node.meta.size;
        let mut out = std::io::BufWriter::new(std::fs::File::create(&tmp).context("failed to create restored file")?);
        let mut offset = 0u64;
        while offset < size {
            let len = (size - offset).min(READ_PIECE as u64) as usize;
            let bytes = repo.read_file_at(&open, offset as usize, len)?;
            if bytes.is_empty() {
                anyhow::bail!("backup ended early at byte {offset} of {size}");
            }
            out.write_all(&bytes).context("failed to write restored file")?;
            offset += bytes.len() as u64;
            if let Some(p) = progress
                && let Ok(mut g) = p.lock()
            {
                g.bytes_done += bytes.len() as u64;
            }
        }
        out.into_inner().map_err(|e| e.into_error()).context("failed to write restored file")?.sync_all().ok();
        Ok(size)
    })();
    match written {
        Ok(size) => {
            std::fs::rename(&tmp, dest).context("failed to move restored file into place")?;
            Ok(size)
        }
        Err(err) => {
            let _ = std::fs::remove_file(&tmp);
            Err(err)
        }
    }
}

/// Restores the given files (from `list`) from the latest snapshot into
/// `restore_dir`, mirroring their paths.
pub async fn restore_files(
    endpoint: &Endpoint,
    relay_url: &RelayUrl,
    buddy_id: EndpointId,
    restore_dir: &Path,
    files: &[BuddyFile],
    progress: Option<ProgressHandle>,
) -> Result<RestoreStats> {
    let started = std::time::Instant::now();
    let (conn, backend) = connect(endpoint, relay_url, buddy_id).await?;
    let meter = netinfo::PathMeter::start(&conn, netinfo::Direction::Received);
    let quality = netinfo::connection_quality(&conn);
    let wanted: Vec<String> = files.iter().filter(|f| !f.deleted).map(|f| f.path.clone()).collect();
    let restore_dir = restore_dir.to_path_buf();
    let job = {
        let backend = backend.clone();
        tokio::task::spawn_blocking(move || -> Result<(usize, u64)> {
            let repo = open(backend)?;
            let snaps = snapshots(&repo)?;
            let Some(latest) = snaps.first() else { anyhow::bail!("this buddy has no snapshot of yours yet") };
            let all = files_in(&repo, latest)?;
            let (mut restored, mut bytes) = (0, 0);
            for (done, path) in wanted.iter().enumerate() {
                if let Some(p) = &progress
                    && let Ok(mut g) = p.lock()
                {
                    g.current_path = Some(path.clone());
                }
                let result = match (all.get(path), safe_join(&restore_dir, path)) {
                    (Some(node), Some(dest)) => restore_node(&repo, node, &dest, progress.as_ref()),
                    (None, _) => Err(anyhow::anyhow!("not in the latest snapshot")),
                    (_, None) => Err(anyhow::anyhow!("unsafe path")),
                };
                match result {
                    Ok(size) => {
                        restored += 1;
                        bytes += size;
                    }
                    Err(err) => tracing::warn!(path = %path, ?err, "failed to restore file"),
                }
                if let Some(p) = &progress
                    && let Ok(mut g) = p.lock()
                {
                    g.completed_files = done + 1;
                    g.current_path = None;
                }
            }
            Ok((restored, bytes))
        })
    };
    let result = job.await.context("restore task failed");
    backend.close();
    let (files_restored, bytes_restored) = result??;
    let traffic = meter.finish(&conn);
    conn.close(0u32.into(), b"done");
    Ok(RestoreStats {
        files_restored,
        bytes_restored,
        duration_ms: started.elapsed().as_millis() as u64,
        connection: Some(quality),
        traffic: Some(traffic),
    })
}

/// Restores one earlier content of a file (as numbered by list_versions),
/// next to where a normal restore would put it: `<path>.v<N>.bak`.
pub async fn restore_version(
    endpoint: &Endpoint,
    relay_url: &RelayUrl,
    buddy_id: EndpointId,
    restore_dir: &Path,
    path: &str,
    version: u32,
) -> Result<RestoreStats> {
    let started = std::time::Instant::now();
    let Some(dest) = safe_join(restore_dir, &format!("{path}.v{version}.bak")) else {
        anyhow::bail!("unsafe path: {path:?}");
    };
    let (conn, backend) = connect(endpoint, relay_url, buddy_id).await?;
    let meter = netinfo::PathMeter::start(&conn, netinfo::Direction::Received);
    let quality = netinfo::connection_quality(&conn);
    let path = path.to_string();
    let job = {
        let backend = backend.clone();
        tokio::task::spawn_blocking(move || -> Result<u64> {
            let repo = open(backend)?;
            let snaps = snapshots(&repo)?;
            let versions = versions_of(&repo, &snaps, &path);
            let Some((_, node)) = (version as usize).checked_sub(1).and_then(|i| versions.get(i)) else {
                anyhow::bail!("that version isn't kept any more");
            };
            restore_node(&repo, node, &dest, None)
        })
    };
    let result = job.await.context("restore task failed");
    backend.close();
    let bytes_restored = result??;
    let traffic = meter.finish(&conn);
    conn.close(0u32.into(), b"done");
    Ok(RestoreStats {
        files_restored: 1,
        bytes_restored,
        duration_ms: started.elapsed().as_millis() as u64,
        connection: Some(quality),
        traffic: Some(traffic),
    })
}

/// The pack id in a "What your buddy sees" path (`data/ab/<id>`), if it is
/// one.
pub fn pack_id(remote: &str) -> Option<&str> {
    let id = remote.strip_prefix("data/")?.split_once('/')?.1;
    (id.len() == 64 && id.bytes().all(|c| c.is_ascii_hexdigit())).then_some(id)
}

/// The first `max` bytes of one pack as the buddy stores it (encrypted).
pub async fn peek_pack(
    endpoint: &Endpoint,
    relay_url: &RelayUrl,
    buddy_id: EndpointId,
    id: &str,
    max: u64,
) -> Result<Vec<u8>> {
    let (conn, _backend) = connect(endpoint, relay_url, buddy_id).await?;
    let size = crate::repo::list(&conn, protocol::RepoFileKind::Pack)
        .await?
        .into_iter()
        .find(|p| p.id == id)
        .map(|p| p.size)
        .context("no such pack on the buddy")?;
    let bytes = crate::repo::read(&conn, protocol::RepoFileKind::Pack, id, 0, Some(size.min(max))).await;
    conn.close(0u32.into(), b"done");
    bytes
}
