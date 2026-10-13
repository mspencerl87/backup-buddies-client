// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

//! Chunked backups, the sender's side (on unless CHUNKED_TRANSFERS=off).
//!
//! Instead of one encrypted copy per file, each buddy gets a restic-format
//! repository built with rustic_core and stored on their side (repo.rs,
//! through repo_backend.rs). Files are split into content-defined chunks,
//! so renaming or moving a file sends nothing and editing one sends only
//! the chunks it touched; each cycle that finds a change is a snapshot.
//! Measured before building it (2026-10-13, 1.9 GB of random data): a
//! renamed 1 GB file and 300 moved photos stored 0 bytes, 1 MB overwritten
//! in the middle of the 1 GB file stored ~1–6 MB, where whole-file backups
//! re-send everything.
//!
//! Only with buddies on client 0.16.0+ (protocol v5); older ones keep
//! getting whole files. The default since 0.19.0.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};
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

/// After finding a buddy too old for chunked backups, how long to use
/// whole files before asking again.
const RECHECK_OLD_BUDDY: Duration = Duration::from_secs(60 * 60);

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Buddies found too old for chunked backups, and when.
static TOO_OLD: LazyLock<Mutex<HashMap<String, Instant>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// On unless CHUNKED_TRANSFERS says off (the default since 0.19.0).
pub fn enabled() -> bool {
    !std::env::var("CHUNKED_TRANSFERS")
        .is_ok_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "off" | "false" | "0" | "no"))
}

/// Where per-buddy state and rustic's cache live (`DATA_DIR/chunked/`).
pub fn init(data_dir: &Path) {
    let _ = DATA_DIR.set(data_dir.join("chunked"));
}

pub(crate) fn state_dir() -> PathBuf {
    DATA_DIR.get().cloned().unwrap_or_else(|| PathBuf::from("/data/chunked"))
}

/// The buddy answered with a protocol version too old for repositories.
#[derive(Debug)]
struct BuddyTooOld(u32);

impl std::fmt::Display for BuddyTooOld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "buddy speaks protocol {} — chunked backups need {REPO_PROTOCOL}", self.0)
    }
}

impl std::error::Error for BuddyTooOld {}

/// One backup cycle for `buddy_id`: chunked when it's on and the buddy can
/// take it, whole files otherwise.
pub async fn run_backup_cycle(
    endpoint: &Endpoint,
    relay_url: &RelayUrl,
    backup_dir: &Path,
    buddy_id: EndpointId,
    progress: Option<&CycleProgressBook>,
) -> Result<BackupCycleStats> {
    let key = buddy_id.to_string();
    let recently_old = TOO_OLD.lock().unwrap().get(&key).is_some_and(|at| at.elapsed() < RECHECK_OLD_BUDDY);
    if !enabled() || recently_old {
        return backup::run_backup_cycle(endpoint, relay_url, backup_dir, buddy_id, progress).await;
    }
    match run_chunked_cycle(endpoint, relay_url, backup_dir, buddy_id, progress).await {
        Err(err) if err.downcast_ref::<BuddyTooOld>().is_some() => {
            tracing::info!(buddy = %key, %err, "buddy's client is too old for chunked backups — sending whole files");
            TOO_OLD.lock().unwrap().insert(key, Instant::now());
            backup::run_backup_cycle(endpoint, relay_url, backup_dir, buddy_id, progress).await
        }
        other => other,
    }
}

/// What we remember per buddy between cycles (`DATA_DIR/chunked/<id>.json`).
#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    /// Hash of every file's path, size and modified time at the last
    /// snapshot: when it matches, nothing changed and the cycle is idle.
    fingerprint: String,
    /// How many files that snapshot held (for the missing-drive check and
    /// counting deletions).
    files: u64,
    last_retention_unix: u64,
}

fn state_path(buddy: &str) -> PathBuf {
    state_dir().join(format!("{buddy}.json"))
}

/// Whether we keep a chunked backup with this buddy (a snapshot was saved
/// to it at some point), so Browse files, restores and History read it
/// rather than whole files.
///
/// Not while chunked backups are turned off: backups to that buddy are
/// whole files again, so that's what there is to browse.
pub(crate) fn has_repo(buddy: &str) -> bool {
    enabled() && state_path(buddy).is_file()
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

pub(crate) async fn run_chunked_cycle(
    endpoint: &Endpoint,
    relay_url: &RelayUrl,
    backup_dir: &Path,
    buddy_id: EndpointId,
    progress: Option<&CycleProgressBook>,
) -> Result<BackupCycleStats> {
    let buddy = buddy_id.to_string();
    let tracker = ProgressTracker::new(progress, &buddy);
    let scan = backup::scan_local_files(backup_dir).await?;
    tracker.update(|p| {
        p.files_total = scan.files.len();
        p.files_checked = scan.files.len();
    });
    let mut state = load_state(&buddy).await;

    // Same guard as whole-file backups: an empty folder where the last
    // snapshot had files is far more likely an unmounted drive. Unlike
    // whole files nothing would be deleted on the buddy (older snapshots
    // keep everything for 30 days), but the new snapshot would be empty.
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
    let retention_due = crate::dashboard::unix_now().saturating_sub(state.last_retention_unix)
        >= RETENTION_EVERY.as_secs()
        && state.files > 0;
    if fp == state.fingerprint && !retention_due {
        return Ok(BackupCycleStats { files_failed: scan.unreadable.len(), failed_paths, ..Default::default() });
    }

    let cycle_started = Instant::now();
    let addr = EndpointAddr::new(buddy_id).with_relay_url(relay_url.clone());
    let conn = endpoint.connect(addr, protocol::ALPN).await.map_err(protocol::explain_connect_error)?;
    let version = backup::buddy_protocol_version(&conn).await;
    if version < REPO_PROTOCOL {
        conn.close(0u32.into(), b"done");
        return Err(BuddyTooOld(version).into());
    }
    let meter = netinfo::PathMeter::start(&conn, netinfo::Direction::Sent);
    let quality = netinfo::connection_quality(&conn);

    let total_bytes: u64 = scan.files.iter().map(|f| f.size).sum();
    tracker.update(|p| {
        p.phase = "sending";
        p.bytes_to_send = total_bytes;
        p.files_to_send = scan.files.len();
        p.sending_started_unix = Some(crate::dashboard::unix_now());
    });
    tracker.start_file("all files (chunked)", total_bytes);

    let backend = Arc::new(BuddyBackend::new(endpoint.clone(), relay_url.clone(), buddy_id, Some(conn.clone())));
    let job = {
        let backend = backend.clone();
        let backup_dir = backup_dir.to_path_buf();
        let rules = Arc::new(scan.rules);
        let counter = tracker.counter.clone();
        let cache = state_dir().join("cache");
        let do_backup = fp != state.fingerprint;
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
        state.files = total;
        state.fingerprint = fp;
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

    // The whole-file copies sent before chunked backups are redundant now
    // that a snapshot holds the same files. Only after a snapshot of a
    // folder read in full, so nothing that couldn't be read this time
    // loses its only copy.
    if outcome.snapshot.is_some()
        && state.files > 0
        && scan.unreadable.is_empty()
        && let Some(idx) = crate::index::try_get()
    {
        retire_whole_files(idx, endpoint, relay_url, buddy_id, &conn).await;
    }
    Ok(stats)
}

/// Deletes, on the buddy, every whole file we sent it before chunked
/// backups (and plaintext-named copies left from 0.14.0's renaming). Like
/// any delete, each becomes a backup copy there for 30 days. Our record of
/// them goes as they do, so this runs once; a failure is retried after the
/// next snapshot.
pub(crate) async fn retire_whole_files(
    idx: &crate::index::Index,
    endpoint: &Endpoint,
    relay_url: &RelayUrl,
    buddy_id: EndpointId,
    conn: &iroh::endpoint::Connection,
) {
    let buddy = buddy_id.to_string();
    let (Ok(sent), Ok(old_names)) = (idx.sent_entries(&buddy), idx.old_names(&buddy)) else { return };
    if sent.is_empty() && old_names.is_empty() {
        return;
    }
    let conn = if conn.close_reason().is_none() {
        conn.clone()
    } else {
        let addr = EndpointAddr::new(buddy_id).with_relay_url(relay_url.clone());
        match endpoint.connect(addr, protocol::ALPN).await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!(%err, "couldn't reach the buddy to retire whole-file copies — will try after the next snapshot");
                return;
            }
        }
    };
    let mut retired = 0;
    for (path, entry) in &sent {
        let Ok(remote) = crate::names::remote_path(path, entry.name_scheme) else { continue };
        match backup::delete_one_file(&conn, &remote).await {
            Ok(()) => {
                let _ = idx.forget_sent(&buddy, std::slice::from_ref(path));
                retired += 1;
            }
            Err(err) => {
                tracing::warn!(%err, "couldn't retire a whole-file copy — will try after the next snapshot");
                return;
            }
        }
    }
    for path in &old_names {
        if backup::delete_one_file(&conn, path).await.is_ok() {
            let _ = idx.forget_old_name(&buddy, path);
        }
    }
    if retired > 0 {
        tracing::info!(buddy = %buddy, files = retired, "whole-file copies retired now that a chunked snapshot holds them");
        crate::activity::record(
            crate::activity::kind::BACKUP,
            Some(&crate::activity::label(&buddy)),
            format!(
                "Moved to a chunked backup: {} sent the old way are kept as backup copies for 30 days",
                crate::activity::plural(retired, "file")
            ),
            Vec::new(),
        );
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
        // Compare with the parent snapshot by size and modified time only,
        // like whole-file backups: inode and ctime aren't stable across a
        // remount of an SMB/NFS share, and would make every file look new.
        backup_opts.parent_opts.ignore_ctime = true;
        backup_opts.parent_opts.ignore_inode = true;
        let source = FilteredSource { root: backup_dir.to_path_buf(), rules };
        Some(repo.archive(&backup_opts, &source, snap, &[backup_dir.to_path_buf()])?)
    } else {
        None
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
    Ok(Outcome { snapshot, retention_ran })
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

/// The backup folder as rustic sees it, walked the way whole-file backups
/// walk it: the exclude list applies, excluded folders aren't opened when
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
