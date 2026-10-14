// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

//! Backups, the sender's side.
//!
//! Each buddy gets a restic-format repository built with rustic_core and
//! stored on their side (repo.rs, through repo_backend.rs). Files are split into content-defined chunks,
//! so renaming or moving a file sends nothing and editing one sends only
//! the chunks it touched; each cycle that finds a change is a snapshot.
//! Measured before building it (2026-10-13, 1.9 GB of random data): a
//! renamed 1 GB file and 300 moved photos stored 0 bytes, 1 MB overwritten
//! in the middle of the 1 GB file stored ~1–6 MB, where the whole-file
//! backups before client 0.19.0 re-sent everything.
//!
//! Buddies need client 0.16.0+ (protocol v5) to store a repository; since
//! client 0.21.0 there's no whole-file fallback for older ones.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl};
use rustic_core::repofile::{MasterKey, Metadata, Node, NodeType, SnapshotFile};
use rustic_core::{
    BackupOptions, ConfigOptions, Credentials, ErrorKind, KeyOptions, Progress, ProgressBars, ProgressType,
    PruneOptions, ReadBackend, ReadSource, ReadSourceEntry, Repository, RepositoryBackends, RepositoryOptions,
    RusticError, RusticProgress, RusticResult, SnapshotOptions,
};
use rustic_core::jiff;
use serde::{Deserialize, Serialize};

use crate::backup::{self, BackupCycleStats, CycleProgressBook, FailedFile, ProgressTracker};
use crate::netinfo;
use crate::protocol;
use crate::repo_backend::BuddyBackend;

/// Protocol version a buddy needs to store a repository (client 0.16.0).
const REPO_PROTOCOL: u32 = 5;

/// Hostname written into every snapshot. Parent detection (which earlier
/// snapshot a backup compares against) goes by host and paths, and the
/// container's own hostname changes with every recreate.
const SNAPSHOT_HOST: &str = "backup-buddies";

/// How often old snapshots are forgotten and the repository pruned.
const RETENTION_EVERY: Duration = Duration::from_secs(24 * 60 * 60);

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Where per-buddy state and rustic's cache live (`DATA_DIR/chunked/`).
pub fn init(data_dir: &Path) {
    let _ = DATA_DIR.set(data_dir.join("chunked"));
}

pub(crate) fn state_dir() -> PathBuf {
    DATA_DIR.get().cloned().unwrap_or_else(|| PathBuf::from("/data/chunked"))
}

/// What we remember per buddy between cycles (`DATA_DIR/chunked/<id>.json`).
#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    /// Hash of every file's path, size and modified time at the last
    /// snapshot: when it matches, nothing changed and the cycle is idle.
    fingerprint: String,
    /// How many files that snapshot held (for the missing-drive check and
    /// counting deletions), and their total size.
    files: u64,
    #[serde(default)]
    bytes: u64,
    last_retention_unix: u64,
    /// Id of the last snapshot saved, checked against the buddy's list
    /// every cycle (see run_backup_cycle). Empty in state from 0.21.0.
    #[serde(default)]
    snapshot_id: String,
}

fn state_path(buddy: &str) -> PathBuf {
    state_dir().join(format!("{buddy}.json"))
}

/// Files and bytes in the last snapshot saved to this buddy, for the
/// dashboard's "You've sent them". None before the first one.
pub(crate) fn last_snapshot_summary(buddy: &str) -> Option<(u64, u64)> {
    let state: State = serde_json::from_slice(&std::fs::read(state_path(buddy)).ok()?).ok()?;
    Some((state.files, state.bytes))
}

/// rustic's options for any repository on a buddy: the shared cache under
/// DATA_DIR, so index and tree data aren't fetched over the network each
/// time.
pub(crate) fn repo_options() -> RepositoryOptions {
    let mut opts = RepositoryOptions::default();
    opts.cache_dir = Some(state_dir().join("cache"));
    opts
}

async fn load_state(buddy: &str) -> State {
    match tokio::fs::read(state_path(buddy)).await {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => State::default(),
    }
}

async fn save_state(buddy: &str, state: &State) -> Result<()> {
    tokio::fs::create_dir_all(state_dir()).await?;
    tokio::fs::write(state_path(buddy), serde_json::to_vec(state)?).await?;
    Ok(())
}

fn fingerprint(scan: &backup::LocalScan) -> String {
    use sha2::{Digest, Sha256};
    let mut files: Vec<_> = scan.files.iter().map(|f| (&f.rel_path, f.size, f.mtime_ns)).collect();
    files.sort();
    let mut hasher = Sha256::new();
    for (path, size, mtime) in files {
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update(size.to_le_bytes());
        hasher.update(mtime.to_le_bytes());
    }
    hex::encode(hasher.finalize())
}

pub(crate) fn master_key() -> MasterKey {
    use base64::Engine as _;
    let key = crate::crypto::repo_key();
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    // MasterKey's fields are public, but its MAC type lives in a module
    // rustic doesn't export, so it's built from its serialized form.
    serde_json::from_value(serde_json::json!({
        "encrypt": b64(&key[..32]),
        "mac": { "k": b64(&key[32..48]), "r": b64(&key[48..]) },
    }))
    .expect("a valid master key")
}

/// One backup cycle for `buddy_id`: a snapshot when anything changed, and
/// forget and prune once a day.
///
/// Every cycle connects, even when nothing changed, and checks the buddy
/// still lists the last snapshot saved there. Seen on the test devices
/// (2026-10-14): a buddy's folder deleted by hand left this side reporting
/// "backup ok" with nothing on the buddy, and an unchanged folder would
/// never have been sent again. A missing snapshot means a full backup now.
/// The check replaces the idle cycle's ping, so it costs the same.
pub async fn run_backup_cycle(
    endpoint: &Endpoint,
    relay_url: &RelayUrl,
    backup_dir: &Path,
    buddy_id: EndpointId,
    progress: Option<&CycleProgressBook>,
) -> Result<BackupCycleStats> {
    let buddy = buddy_id.to_string();
    let tracker = ProgressTracker::new(progress, &buddy);
    let scan = backup::scan_local_files(backup_dir).await?;
    tracker.update(|p| p.files_total = scan.files.len());
    let mut state = load_state(&buddy).await;

    // An empty folder where the last snapshot had files is far more likely
    // an unmounted drive. Nothing would be lost on the buddy (older
    // snapshots keep everything for 30 days), but the new snapshot would
    // be empty.
    if backup::looks_like_missing_drive(scan.files.len(), scan.unreadable.len(), state.files as usize)
        && !backup::allow_empty_backup_dir()
    {
        anyhow::bail!(
            "your backup folder ({}) looks empty, but your last backup to this buddy had {} file(s) — \
             not backing up an empty folder. Is the drive with your files mounted? If you really did \
             delete everything, set ALLOW_EMPTY_BACKUP_DIR=true in .env and restart (then remove it again).",
            crate::host_dir_label(backup_dir, "BACKUP_DIR_HOST"),
            state.files
        );
    }

    let failed_paths: Vec<FailedFile> = scan
        .unreadable
        .iter()
        .take(10)
        .map(|path| FailedFile {
            path: if path.is_empty() { "(backup folder)".to_string() } else { path.clone() },
            reason: Some("can't open this on this device — check permissions"),
        })
        .collect();
    let fp = fingerprint(&scan);

    let cycle_started = Instant::now();
    let addr = EndpointAddr::new(buddy_id).with_relay_url(relay_url.clone());
    let conn = endpoint.connect(addr, protocol::ALPN).await.map_err(protocol::explain_connect_error)?;
    let version = backup::buddy_protocol_version(&conn).await;
    if version < REPO_PROTOCOL {
        conn.close(0u32.into(), b"done");
        anyhow::bail!(
            "your buddy's client is too old to store your backup (protocol {version}, needs {REPO_PROTOCOL}) — ask them to update"
        );
    }
    let meter = netinfo::PathMeter::start(&conn, netinfo::Direction::Sent);
    let quality = netinfo::connection_quality(&conn);

    if !state.fingerprint.is_empty() {
        let snaps = crate::repo::list(&conn, protocol::RepoFileKind::Snapshot).await?;
        if backup_lost(&state, &snaps) {
            tracing::warn!(buddy = %buddy, "the buddy no longer has the backup saved there — backing up in full again");
            crate::activity::record(
                crate::activity::kind::PROBLEM,
                Some(&crate::activity::label(&buddy)),
                "No longer has your backup (deleted on their side?) — backing it up again in full",
                Vec::new(),
            );
            state = State::default();
        }
    }
    let do_backup = fp != state.fingerprint;
    let retention_due = crate::dashboard::unix_now().saturating_sub(state.last_retention_unix)
        >= RETENTION_EVERY.as_secs()
        && state.files > 0;
    if !do_backup && !retention_due {
        let traffic = meter.finish(&conn);
        conn.close(0u32.into(), b"done");
        return Ok(BackupCycleStats {
            connection: Some(quality),
            traffic: Some(traffic),
            files_failed: scan.unreadable.len(),
            failed_paths,
            ..Default::default()
        });
    }

    let total_bytes: u64 = scan.files.iter().map(|f| f.size).sum();
    // rustic's byte counter (CycleProgressBars) drives the bar through
    // the tracker's counter, over every byte it reads.
    tracker.update(|p| {
        p.phase = "sending";
        p.bytes_total = total_bytes;
        p.sending_started_unix = Some(crate::dashboard::unix_now());
    });

    let backend = Arc::new(BuddyBackend::new(endpoint.clone(), relay_url.clone(), buddy_id, Some(conn.clone())));
    let job = {
        let backend = backend.clone();
        let backup_dir = backup_dir.to_path_buf();
        let rules = Arc::new(scan.rules);
        let counter = tracker.counter.clone();
        let cache = state_dir().join("cache");
        tokio::task::spawn_blocking(move || {
            snapshot_and_tidy(backend, &backup_dir, rules, counter, cache, do_backup, retention_due)
        })
    };
    let outcome = job.await.context("chunked backup task failed");
    backend.close();
    let outcome = outcome?;
    let traffic = meter.finish(&backend.connection_now().unwrap_or_else(|| conn.clone()));

    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(err) => {
            if let Some(reason) = backend.refusal() {
                anyhow::bail!("{}", reason.message());
            }
            return Err(err);
        }
    };

    let mut stats = BackupCycleStats {
        duration_ms: cycle_started.elapsed().as_millis() as u64,
        connection: Some(quality),
        traffic: Some(traffic),
        files_failed: scan.unreadable.len(),
        failed_paths,
        ..Default::default()
    };
    if let Some(snap) = &outcome.snapshot {
        let s = snap.summary.as_ref();
        let (new, changed, unmodified, total) = s
            .map(|s| (s.files_new, s.files_changed, s.files_unmodified, s.total_files_processed))
            .unwrap_or_default();
        stats.files_sent = (new + changed) as usize;
        stats.files_deleted = state.files.saturating_sub(changed + unmodified) as usize;
        stats.bytes_sent = s.map(|s| s.data_added_packed).unwrap_or(0);
        stats.sent_paths = outcome.sent_paths.clone();
        stats.deleted_paths = outcome.deleted_paths.clone();
        state.files = total;
        state.bytes = s.map(|s| s.total_bytes_processed).unwrap_or(0);
        state.fingerprint = fp;
        state.snapshot_id = snap.id.to_hex().to_string();
        tracing::info!(
            buddy = %buddy,
            files_new = new,
            files_changed = changed,
            files_deleted = stats.files_deleted,
            bytes_added = stats.bytes_sent,
            "chunked backup snapshot saved"
        );
    }
    if outcome.retention_ran {
        state.last_retention_unix = crate::dashboard::unix_now();
    }
    if let Err(err) = save_state(&buddy, &state).await {
        tracing::warn!(?err, "couldn't save chunked backup state — the next cycle will check everything again");
    }
    Ok(stats)
}

/// Whether the buddy lost the backup we saved there: our last snapshot
/// isn't in its list (or, for state from before snapshot ids were kept,
/// it has no snapshots at all).
fn backup_lost(state: &State, snaps: &[protocol::RepoFileEntry]) -> bool {
    if state.snapshot_id.is_empty() {
        snaps.is_empty()
    } else {
        !snaps.iter().any(|s| s.id == state.snapshot_id)
    }
}

/// Most CPUs a backup's rustic threads run on. rustic sizes its thread
/// pools to the CPUs it can see: a backup peaked at ~560 MB on 16 CPUs and
/// ~250 MB on 2 in testing, and a buddy box is usually busy with other
/// things too.
const MAX_BACKUP_CPUS: usize = 4;

/// Narrows the calling thread to MAX_BACKUP_CPUS CPUs until dropped.
/// rustic's pools (pariter's available_parallelism, rayon's) follow the
/// affinity of the thread that starts them, and threads inherit it. Put
/// back afterwards, since tokio reuses this blocking thread.
struct CpuCap {
    #[cfg(target_os = "linux")]
    saved: Option<libc::cpu_set_t>,
}

impl CpuCap {
    #[cfg(target_os = "linux")]
    fn new() -> Self {
        // SAFETY: plain libc calls on a zeroed cpu_set_t for this thread
        // (pid 0); a failure leaves the affinity as it was.
        let saved = unsafe {
            let size = std::mem::size_of::<libc::cpu_set_t>();
            let mut current: libc::cpu_set_t = std::mem::zeroed();
            if libc::sched_getaffinity(0, size, &mut current) != 0
                || (libc::CPU_COUNT(&current) as usize) <= MAX_BACKUP_CPUS
            {
                None
            } else {
                let mut narrowed: libc::cpu_set_t = std::mem::zeroed();
                let mut taken = 0;
                for cpu in 0..libc::CPU_SETSIZE as usize {
                    if taken < MAX_BACKUP_CPUS && libc::CPU_ISSET(cpu, &current) {
                        libc::CPU_SET(cpu, &mut narrowed);
                        taken += 1;
                    }
                }
                (libc::sched_setaffinity(0, size, &narrowed) == 0).then_some(current)
            }
        };
        Self { saved }
    }

    #[cfg(not(target_os = "linux"))]
    fn new() -> Self {
        Self {}
    }
}

impl Drop for CpuCap {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if let Some(saved) = &self.saved {
            // SAFETY: restores the mask read in new().
            unsafe {
                libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), saved);
            }
        }
    }
}

struct Outcome {
    snapshot: Option<SnapshotFile>,
    retention_ran: bool,
    /// What the new snapshot added or changed, and dropped, against its
    /// parent, for the Activity line (capped at ACTIVITY_PATHS).
    sent_paths: Vec<String>,
    deleted_paths: Vec<String>,
}

/// Most paths listed per Activity line.
const ACTIVITY_PATHS: usize = 200;

/// Which files the new snapshot added or changed, and which it no longer
/// has, compared with its parent. Only for Activity, so a failure just
/// leaves the lists empty.
fn snapshot_changes<S: rustic_core::IndexedTree>(
    repo: &Repository<S>,
    snap: &SnapshotFile,
) -> Result<(Vec<String>, Vec<String>)> {
    let Some(new_root) = crate::chunked_restore::root_tree(repo, snap) else { return Ok(Default::default()) };
    let parent = match snap.parent {
        Some(id) => repo.get_all_snapshots()?.into_iter().find(|s| s.id == id),
        None => None,
    };
    let old_root = parent.as_ref().and_then(|p| crate::chunked_restore::root_tree(repo, p));
    let mut sent = Vec::new();
    crate::chunked_restore::changed_in(repo, old_root, new_root, "", &mut sent, ACTIVITY_PATHS)?;
    let mut deleted = std::collections::HashMap::new();
    if let Some(old_root) = old_root {
        crate::chunked_restore::missing_from(repo, old_root, Some(new_root), "", &mut deleted)?;
    }
    let mut deleted: Vec<String> = deleted.into_keys().collect();
    deleted.sort();
    deleted.truncate(ACTIVITY_PATHS);
    Ok((sent, deleted))
}

/// The rustic part of a cycle, on a blocking thread: open (or create) the
/// repository, back up if anything changed, and forget and prune when due.
fn snapshot_and_tidy(
    backend: Arc<BuddyBackend>,
    backup_dir: &Path,
    rules: Arc<crate::excludes::Rules>,
    counter: Arc<AtomicU64>,
    cache: PathBuf,
    do_backup: bool,
    retention_due: bool,
) -> Result<Outcome> {
    let _cap = CpuCap::new();
    let backends = RepositoryBackends::new(backend.clone(), None);
    let mut opts = repo_options();
    opts.cache_dir = Some(cache);
    let creds = Credentials::Masterkey(master_key());
    let repo = Repository::new_with_progress(&opts, &backends, CycleProgressBars { counter })?;
    let has_config = !backend.list(rustic_core::FileType::Config)?.is_empty();
    let repo = if has_config {
        repo.open(&creds)?
    } else {
        tracing::info!("creating the chunked backup repository on this buddy");
        repo.init(&creds, &KeyOptions::default(), &ConfigOptions::default())?
    };
    let repo = repo.to_indexed_ids()?;

    let snapshot = if do_backup {
        let snap = SnapshotOptions::default().host(Some(SNAPSHOT_HOST.to_string())).to_snapshot()?;
        let mut backup_opts = BackupOptions::default();
        // Compare with the parent snapshot by size and modified time only:
        // inode and ctime aren't stable across a remount of an SMB/NFS
        // share, and would make every file look new.
        backup_opts.parent_opts.ignore_ctime = true;
        backup_opts.parent_opts.ignore_inode = true;
        let source = FilteredSource { root: backup_dir.to_path_buf(), rules };
        Some(repo.archive(&backup_opts, &source, snap, &[backup_dir.to_path_buf()])?)
    } else {
        None
    };
    // The index loaded above predates this snapshot's own trees, so the
    // comparison reads a freshly loaded one (the new index files are
    // small; the rest comes from the cache).
    let (sent_paths, deleted_paths) = match &snapshot {
        Some(snap) => Repository::new(&opts, &backends)
            .and_then(|r| r.open(&creds))
            .and_then(|r| r.to_indexed_ids())
            .map_err(anyhow::Error::from)
            .and_then(|fresh| snapshot_changes(&fresh, snap))
            .unwrap_or_else(|err| {
                tracing::debug!(?err, "couldn't list what this snapshot changed");
                Default::default()
            }),
        None => Default::default(),
    };

    let mut retention_ran = false;
    if retention_due {
        let snaps = repo.get_all_snapshots()?;
        let now = jiff::Timestamp::now();
        let forget = snapshots_to_forget(snaps.iter().map(|s| (s.id, s.time.timestamp())), now);
        if !forget.is_empty() {
            tracing::info!(count = forget.len(), "forgetting old chunked backup snapshots");
            repo.delete_snapshots(&forget)?;
        }
        let mut prune_opts = PruneOptions::default();
        // One writer per repository (this device), so unused packs can go
        // right away instead of after rustic's default day of waiting for
        // other backups that might still be writing.
        prune_opts.instant_delete = true;
        let plan = repo.prune_plan(&prune_opts)?;
        repo.prune(&prune_opts, plan)?;
        retention_ran = true;
    }
    Ok(Outcome { snapshot, retention_ran, sent_paths, deleted_paths })
}

/// Which snapshots the retention policy drops: every one from the last 24
/// hours stays, then the newest of each hour up to 2 days, then the newest
/// of each day up to 30 days. The newest snapshot always stays.
fn snapshots_to_forget<I: Clone>(snaps: impl Iterator<Item = (I, jiff::Timestamp)>, now: jiff::Timestamp) -> Vec<I> {
    let mut snaps: Vec<_> = snaps.collect();
    snaps.sort_by_key(|s| std::cmp::Reverse(s.1));
    let mut kept_hours = std::collections::HashSet::new();
    let mut kept_days = std::collections::HashSet::new();
    let mut forget = Vec::new();
    for (i, (id, at)) in snaps.into_iter().enumerate() {
        let age = now.as_second().saturating_sub(at.as_second());
        // Each age gets one rule: a snapshot that loses its hour's slot
        // isn't then kept as its day's.
        let keep = if i == 0 || age <= 24 * 3600 {
            true
        } else if age <= 48 * 3600 {
            kept_hours.insert(at.as_second().div_euclid(3600))
        } else if age <= 30 * 86400 {
            kept_days.insert(at.as_second().div_euclid(86400))
        } else {
            false
        };
        if !keep {
            forget.push(id);
        }
    }
    forget
}

/// Feeds rustic progress into the buddy card's bar: the backup's byte
/// counter is the one that matters; the rest stay hidden.
#[derive(Debug)]
struct CycleProgressBars {
    counter: Arc<AtomicU64>,
}

impl ProgressBars for CycleProgressBars {
    fn progress(&self, progress_type: ProgressType, prefix: &str) -> Progress {
        if matches!(progress_type, ProgressType::Bytes) && prefix.starts_with("backing up") {
            Progress::new(CounterProgress(self.counter.clone()))
        } else {
            Progress::hidden()
        }
    }
}

#[derive(Debug)]
struct CounterProgress(Arc<AtomicU64>);

impl RusticProgress for CounterProgress {
    fn is_hidden(&self) -> bool {
        false
    }
    fn set_length(&self, _len: u64) {}
    fn set_title(&self, _title: &str) {}
    fn inc(&self, inc: u64) {
        self.0.fetch_add(inc, Ordering::Relaxed);
    }
    fn finish(&self) {}
}

/// The backup folder as rustic sees it, walked the way the scan
/// (backup.rs's scan_local_files) walks it: the exclude list applies, excluded folders aren't opened when
/// no `!` line could bring something back from inside them, and a folder
/// that can't be read is logged and skipped rather than failing the
/// snapshot. Sorted by name, which rustic's tree building needs.
struct FilteredSource {
    root: PathBuf,
    rules: Arc<crate::excludes::Rules>,
}

/// Opens a file only when rustic gets to it.
#[derive(Debug)]
struct LocalOpen(PathBuf);

impl rustic_core::ReadSourceOpen for LocalOpen {
    type Reader = std::fs::File;

    fn open(self) -> RusticResult<Self::Reader> {
        std::fs::File::open(&self.0).map_err(|err| {
            RusticError::with_source(ErrorKind::InputOutput, "Failed to open `{path}`.", err)
                .attach_context("path", self.0.display().to_string())
        })
    }
}

type SourceIter = Box<dyn Iterator<Item = RusticResult<ReadSourceEntry<LocalOpen>>> + Send>;

impl ReadSource for FilteredSource {
    type Open = LocalOpen;
    type Iter = SourceIter;

    fn size(&self) -> RusticResult<Option<u64>> {
        Ok(None)
    }

    fn entries(&self) -> Self::Iter {
        let root = self.root.clone();
        let rules = self.rules.clone();
        let skip_folders = rules.can_skip_folders();
        let walk_root = root.clone();
        let walk_rules = rules.clone();
        let walk = walkdir::WalkDir::new(&root)
            .follow_links(false)
            .min_depth(1)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(move |e| {
                !(skip_folders
                    && e.file_type().is_dir()
                    && walk_rules.is_excluded(&backup::rel_to(&walk_root, e.path())))
            });
        Box::new(walk.filter_map(move |entry| {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    tracing::warn!(%err, "can't read part of BACKUP_DIR — leaving it out of this snapshot");
                    return None;
                }
            };
            let rel = backup::rel_to(&root, entry.path());
            if !entry.file_type().is_dir() && rules.is_excluded(&rel) {
                return None;
            }
            match node_for(&entry) {
                Ok(Some(node)) => {
                    let open = node.is_file().then(|| LocalOpen(entry.path().to_path_buf()));
                    Some(Ok(ReadSourceEntry { path: entry.path().to_path_buf(), node, open }))
                }
                // Sockets, devices and the like: not backed up, like now.
                Ok(None) => None,
                Err(err) => {
                    tracing::warn!(path = %rel, %err, "can't read this file's details — leaving it out of this snapshot");
                    None
                }
            }
        }))
    }
}

fn node_for(entry: &walkdir::DirEntry) -> std::io::Result<Option<Node>> {
    let meta = entry.metadata().map_err(std::io::Error::other)?;
    let ft = entry.file_type();
    let node_type = if ft.is_dir() {
        NodeType::Dir
    } else if ft.is_file() {
        NodeType::File
    } else if ft.is_symlink() {
        NodeType::from_link(&std::fs::read_link(entry.path())?)
    } else {
        return Ok(None);
    };
    let mut m = Metadata {
        size: if ft.is_file() { meta.len() } else { 0 },
        mtime: meta.modified().ok().and_then(|t| jiff::Timestamp::try_from(t).ok()),
        ..Default::default()
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        m.mode = Some(meta.mode());
        m.uid = Some(meta.uid());
        m.gid = Some(meta.gid());
        m.inode = meta.ino();
        m.device_id = meta.dev();
        m.links = meta.nlink();
        m.ctime = jiff::Timestamp::new(meta.ctime(), meta.ctime_nsec() as i32).ok();
    }
    Ok(Some(Node::new_node(entry.file_name(), node_type, m)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_last_snapshot_means_the_backup_was_lost() {
        let entry = |id: &str| protocol::RepoFileEntry { id: id.to_string(), size: 1 };
        let state = State { fingerprint: "f".into(), snapshot_id: "b".repeat(64), ..Default::default() };
        assert!(!backup_lost(&state, &[entry(&"a".repeat(64)), entry(&"b".repeat(64))]));
        assert!(backup_lost(&state, &[entry(&"a".repeat(64))]), "only an older one");
        assert!(backup_lost(&state, &[]));
        let old = State { fingerprint: "f".into(), ..Default::default() };
        assert!(!backup_lost(&old, &[entry(&"a".repeat(64))]), "no id kept yet: any snapshot will do");
        assert!(backup_lost(&old, &[]));
    }

    #[test]
    fn retention_keeps_recent_hourly_then_daily() {
        let now = jiff::Timestamp::from_second(100 * 86400).unwrap();
        let ago = |h: i64| jiff::Timestamp::from_second(now.as_second() - h * 3600).unwrap();
        // Two snapshots inside each of these hours, "b" the older one.
        let at = |h: i64, secs: i64| jiff::Timestamp::from_second(ago(h).as_second() + secs).unwrap();
        let mut snaps = Vec::new();
        for h in [1, 23, 30, 47, 72, 24 * 29, 24 * 31] {
            snaps.push((format!("{h}a"), at(h, 600)));
            snaps.push((format!("{h}b"), at(h, 300)));
        }
        let mut forgotten = snapshots_to_forget(snaps.into_iter(), now);
        forgotten.sort();
        // Within a day: all kept. 30 h and 47 h: the older of each hour's
        // pair goes. 72 h and 29 days: one per day. 31 days: both go.
        assert_eq!(forgotten, ["30b", "47b", "696b", "72b", "744a", "744b"]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cpu_cap_narrows_this_thread_and_puts_it_back() {
        let count = || {
            // SAFETY: reads this thread's affinity into a zeroed set.
            unsafe {
                let mut set: libc::cpu_set_t = std::mem::zeroed();
                libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set);
                libc::CPU_COUNT(&set) as usize
            }
        };
        let before = count();
        {
            let _cap = CpuCap::new();
            assert_eq!(count(), before.min(MAX_BACKUP_CPUS));
            assert_eq!(std::thread::available_parallelism().unwrap().get(), before.min(MAX_BACKUP_CPUS));
        }
        assert_eq!(count(), before);
    }

    #[test]
    fn the_newest_snapshot_always_stays() {
        let now = jiff::Timestamp::from_second(1000 * 86400).unwrap();
        let old = jiff::Timestamp::from_second(10 * 86400).unwrap();
        assert!(snapshots_to_forget(std::iter::once(("only", old)), now).is_empty());
    }
}
