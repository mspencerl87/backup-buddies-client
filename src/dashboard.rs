// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};

use age::secrecy::SecretString;
use axum::{
    extract::{Path as AxumPath, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use iroh::{Endpoint, EndpointId, RelayUrl};
use serde::{Deserialize, Serialize};

use crate::bandwidth::{BandwidthBook, BandwidthTotals};
use crate::netinfo::ConnectionQuality;
use crate::protocol::ListEntry;
use crate::receive::{self, PledgeBook};

// Brand assets, shared with apps/web/assets (the canonical copy — see
// that directory's files and this crate's Dockerfile for how they get
// here). Embedded at compile time rather than served from disk: this
// dashboard has no static-file directory of its own, and two tiny SVGs
// aren't worth adding one for.
const MARK_SVG: &str = include_str!("../assets/mark.svg");
const FAVICON_SVG: &str = include_str!("../assets/favicon.svg");

/// One entry per buddy, updated by main.rs's outbound loop every time it
/// finishes a backup cycle (or a ping, for a buddy with no BACKUP_DIR) —
/// what the dashboard shows as "last cycle" is exactly what that loop just
/// did, not a separate probe.
#[derive(Clone, Serialize)]
pub struct CycleRecord {
    pub label: String,
    pub at: u64,
    pub kind: &'static str, // "backup" | "ping"
    pub ok: bool,
    pub detail: String,
    pub files_sent: Option<usize>,
    pub files_deleted: Option<usize>,
    // Transfer metrics for this cycle — None for a no-op cycle (nothing
    // changed, no connection opened), a failed cycle, or a ping. Straight
    // off the connection's own QUIC stats, not derived from file sizes, so
    // they reflect what actually went over the wire including protocol
    // overhead. The dashboard computes a rate from bytes_sent/duration_ms
    // rather than this storing one, to keep the raw numbers as the source
    // of truth.
    pub bytes_sent: Option<u64>,
    pub duration_ms: Option<u64>,
    pub connection: Option<ConnectionQuality>,
    // How many files this cycle failed to send/delete, and a capped
    // sample of which ones — None for a ping (not applicable). A cycle
    // with any failures is reported as not-`ok`, same as a connection
    // failure, since "ran but some files are stuck" deserves the same
    // attention as "didn't run at all".
    pub files_failed: Option<usize>,
    pub failed_files: Vec<FailedFileView>,
    // Set by record_cycle below, not by the caller: when this cycle
    // succeeded, last_ok_at is this cycle's own `at`; when it didn't,
    // it's carried forward from whatever the last successful cycle was —
    // so the dashboard can show "last synced 2h ago" even while recent
    // attempts have been failing, rather than losing that fact the moment
    // the first failure overwrites the record.
    pub last_ok_at: Option<u64>,
    // Same idea: how many cycles in a row have failed, reset to 0 the
    // moment one succeeds. One bad cycle reads very differently from
    // twenty in a row.
    pub consecutive_failures: u32,
    // Set by the caller (main.rs), distinct from `ok`: true when this
    // cycle actually moved data (sent or deleted at least one file) *or*
    // found nothing that needed doing at all (a fully idle, already-in-
    // sync cycle). False when every attempted put/delete failed, or the
    // connection itself failed. A buddy with one permanently-stuck file
    // alongside eleven healthy ones should never look exactly like a
    // buddy where nothing has ever synced — `ok` conflates the two (any
    // failure at all makes a cycle not-`ok`, which is right for the
    // "backup failed" pill), so staleness needs its own signal.
    pub made_progress: bool,
    // Set by record_cycle below, same pattern as last_ok_at but driven by
    // `made_progress` instead of `ok` — this is what "stale" and "last
    // synced" should actually be measured against.
    pub last_synced_at: Option<u64>,
}

/// One failed path plus why, when we know why — see
/// backup::reject_reason_from_err for how `reason` gets populated. Its own
/// type (rather than reusing backup::FailedFile directly) so this module
/// controls the wire shape independent of backup.rs's internals.
#[derive(Clone, Serialize)]
pub struct FailedFileView {
    pub path: String,
    pub reason: Option<&'static str>,
}

impl From<crate::backup::FailedFile> for FailedFileView {
    fn from(f: crate::backup::FailedFile) -> Self {
        Self { path: f.path, reason: f.reason }
    }
}

pub type CycleBook = Arc<Mutex<HashMap<String, CycleRecord>>>;

pub fn record_cycle(cycle_stats: &CycleBook, node_id: &str, mut record: CycleRecord) {
    let mut book = cycle_stats.lock().unwrap();
    let previous = book.get(node_id);
    record.last_ok_at = if record.ok {
        Some(record.at)
    } else {
        previous.and_then(|r| r.last_ok_at)
    };
    record.consecutive_failures =
        if record.ok { 0 } else { previous.map(|r| r.consecutive_failures).unwrap_or(0) + 1 };
    record.last_synced_at = if record.made_progress {
        Some(record.at)
    } else {
        previous.and_then(|r| r.last_synced_at)
    };
    book.insert(node_id.to_string(), record);
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// One buddy's most recent reconciliation result — see
/// backup::reconcile_with_buddy for what this actually checks (the
/// manifest vs. the buddy's real stored files, not just our local diff).
/// Updated by main.rs's outbound loop every time it runs a reconciliation
/// pass (roughly every 10 minutes per buddy, not every ordinary cycle).
#[derive(Clone, Serialize)]
pub struct ReconcileRecord {
    pub at: u64,
    pub checked: usize,
    pub missing_on_buddy: Vec<String>,
    pub unexpected_on_buddy: Vec<String>,
    // Set when the reconciliation attempt itself failed (couldn't connect,
    // couldn't list) rather than succeeding and finding drift — a
    // different situation from "checked and it's clean" or "checked and
    // found a mismatch", so the dashboard can tell them apart instead of
    // an error silently looking identical to "never checked".
    pub error: Option<String>,
}

pub type ReconcileBook = Arc<Mutex<HashMap<String, ReconcileRecord>>>;

#[derive(Clone)]
struct AppState {
    node_id: String,
    // Config/state only (identity key, manifests, ledgers).
    data_dir: PathBuf,
    // What buddies store with us — BUDDY_FILES_DIR/<their node id>/.
    buddy_files_dir: PathBuf,
    // Where dashboard restores land — RESTORE_DIR/<their node id>/.
    restore_dir: PathBuf,
    // The same folder as the person knows it on the host (see
    // main.rs's host_path_for_display) — what restore results show.
    restore_dir_display: String,
    backup_dir: Option<PathBuf>,
    pledge_book: PledgeBook,
    bandwidth_book: BandwidthBook,
    cycle_stats: CycleBook,
    reconcile_stats: ReconcileBook,
    // Live progress of any backup cycle running right now — see
    // backup::CycleProgress.
    cycle_progress: crate::backup::CycleProgressBook,
    // This device's own label, as set in the web dashboard's Devices card —
    // see main.rs's self_label for where it's filled in. None until the
    // first successful poll of /devices/me/buddies, or if never labeled.
    self_label: Arc<Mutex<Option<String>>>,
    // Endpoint ids currently visible via mDNS on the local network — see
    // main.rs's mdns_peers for where it's maintained. A live count, not a
    // one-time "ever seen" log — Syncthing-style discovery visibility.
    mdns_peers: Arc<Mutex<HashSet<EndpointId>>>,
    // Newest client version the server advertises (see update_check.rs);
    // None until a check has succeeded, or if checking is off.
    latest_version: crate::update_check::LatestVersion,
    // How often the outbound loop polls/backs up — see main.rs's
    // BACKUP_CYCLE_INTERVAL_SECS. Not configurable yet, just surfaced so
    // the dashboard shows the real value instead of a hardcoded guess.
    cycle_interval_secs: u64,
    endpoint: Endpoint,
    relay_url: RelayUrl,
    passphrase: SecretString,
    stale_after_secs: u64,
    restore_progress: RestoreProgressBook,
    // Set once, when the dashboard starts serving — i.e. process start for
    // all practical purposes, since the dashboard comes up alongside the
    // rest of main.rs. Used only to report uptime; never reset.
    started_at: Instant,
}

/// One entry per buddy we've ever kicked off a restore for — only the
/// latest one (a new restore to the same buddy just overwrites the
/// previous entry). Lets GET /api/buddies/:id/restore-progress poll the
/// state of a restore while the POST that started it is still in flight,
/// as a second, separate request — see restore.rs's RestoreProgress doc
/// comment for the fuller reasoning.
type RestoreProgressBook = Arc<Mutex<HashMap<String, crate::restore::ProgressHandle>>>;

#[derive(Serialize)]
struct BuddyStatus {
    node_id: String,
    label: Option<String>,
    // What they've pledged us, and how much of it we've used storing
    // their files (see receive.rs's pledge enforcement).
    pledged_bytes: u64,
    received_bytes_counted: u64,
    received_files: usize,
    received_total_bytes: u64,
    // What *we've* sent *them*, per our own manifest for that buddy.
    sent_files: usize,
    sent_bytes: u64,
    last_cycle: Option<CycleRecord>,
    // Live progress of a backup cycle running right now, if one is — see
    // backup::CycleProgress. Absent between cycles.
    in_progress: Option<crate::backup::CycleProgress>,
    // True when this buddy hasn't had a successful cycle in over
    // stale_after_secs (or has never had one at all despite trying) —
    // computed here rather than left to the frontend so the threshold
    // lives in one place (Config::stale_after_secs).
    stale: bool,
    // Most recent reconciliation result (see backup::reconcile_with_buddy)
    // — absent until the first one has actually run, roughly 10 minutes
    // after this buddy pairing starts sending files.
    last_reconcile: Option<ReconcileRecord>,
}

/// Physical space on the filesystem backing `buddy_files_dir` — where every
/// buddy's `<their id>/` folder lives (which may be a different disk from
/// `data_dir`'s config). This is the actual disk, not the
/// sum of pledges: pledges are promises about how much we'll *accept*,
/// this is what the OS says is really there. The two can and do diverge
/// (pledges made before the disk filled up, other things sharing the same
/// volume), which is exactly what the dashboard needs to show.
#[derive(Serialize)]
struct DiskStatus {
    total_bytes: u64,
    available_bytes: u64,
    used_bytes: u64,
}

/// What's actually sitting in `backup_dir` right now, independent of
/// what's made it into any buddy's manifest yet — a plain re-scan (see
/// backup::local_backup_summary), not a sync-protocol number.
#[derive(Serialize)]
struct LocalBackupStatus {
    file_count: usize,
    total_bytes: u64,
}

#[derive(Serialize)]
struct StatusResponse {
    node_id: String,
    // This device's own label (see AppState::self_label's comment) — None
    // until it's known. The frontend falls back to showing node_id when
    // this is absent.
    label: Option<String>,
    backup_dir: Option<String>,
    data_dir: String,
    buddy_files_dir: String,
    restore_dir: String,
    // Build version and process uptime — the same two numbers a
    // Syncthing-style "This Device" panel shows, so a person checking the
    // dashboard can tell at a glance whether this device has restarted
    // recently and which build it's running.
    version: &'static str,
    // Newest version the server advertises, and whether this build is older
    // than it. latest_version is None when the check hasn't succeeded (yet,
    // or ever — offline, or turned off), which the UI must show as "unknown",
    // not "up to date".
    latest_version: Option<String>,
    update_available: bool,
    // The command that updates *this kind* of install — see the Dockerfile's
    // BB_INSTALL_KIND. Image installs just pull; source installs rebuild,
    // which install.sh --update does.
    update_command: &'static str,
    uptime_secs: u64,
    // How many buddies are visible on the local network via mDNS right
    // now, and the fixed interval (seconds) the outbound loop polls/backs
    // up on — both Syncthing-style discovery/rescan signals, surfaced
    // read-only (see AppState's comments on mdns_peers/cycle_interval_secs).
    mdns_peers_visible: usize,
    cycle_interval_secs: u64,
    local_backup: Option<LocalBackupStatus>,
    disk: Option<DiskStatus>,
    // Sum of every buddy's pledged_bytes — the total we've promised to
    // store for others on this same disk. Compared against `disk` on the
    // dashboard so an operator can see at a glance whether their pledges
    // actually fit.
    pledged_out_total_bytes: u64,
    buddies: Vec<BuddyStatus>,
    // Lifetime bytes this device has moved via relay.filegarden.net vs.
    // direct peer-to-peer, across every backup, restore, and buddy-served
    // request — see bandwidth.rs. Global, not per-buddy: what matters here
    // is how much of this device's traffic costs relay bandwidth, same
    // number regardless of which buddy it was with.
    bandwidth: BandwidthTotals,
}

// A buddy's DiskStatsResponse (their numbers, from the wire protocol)
// plus our own local read on the connection we just used to ask for it
// (ours alone — not something they report about themselves). Flattened
// into one JSON object so the frontend doesn't need to know these came
// from two different places.
#[derive(Serialize)]
struct BuddyDiskResponse {
    #[serde(flatten)]
    disk: crate::protocol::DiskStatsResponse,
    connection: ConnectionQuality,
}

#[derive(Serialize)]
struct RestoreResponse {
    restored_files: usize,
    dir: String,
    bytes_restored: u64,
    duration_ms: u64,
    connection: Option<ConnectionQuality>,
}

/// Request body for POST /api/restore/:node_id. `paths` absent or empty
/// means "restore everything" (what the plain "Restore everything" button
/// sends) — the file browser sends specific paths once the person has
/// picked them.
#[derive(Deserialize, Default)]
struct RestoreRequest {
    #[serde(default)]
    paths: Vec<String>,
}

#[derive(Deserialize)]
struct PathQuery {
    path: String,
}

/// Request body for POST /api/restore-version/:node_id — restores one
/// specific backup slot of one file, rather than the live copy.
#[derive(Deserialize)]
struct RestoreVersionRequest {
    path: String,
    version: u32,
}

/// Binds and serves the dashboard until the process shuts down. Meant to
/// run alongside the accept/outbound loops in main.rs's tokio::select!,
/// not instead of them — it only reads the same state those loops already
/// maintain (pledge_book, cycle_stats) plus whatever's on disk (manifests,
/// received/), it never competes with them for the sync protocol itself.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    bind_addr: &str,
    node_id: String,
    data_dir: PathBuf,
    buddy_files_dir: PathBuf,
    restore_dir: PathBuf,
    restore_dir_display: String,
    backup_dir: Option<PathBuf>,
    pledge_book: PledgeBook,
    bandwidth_book: BandwidthBook,
    cycle_stats: CycleBook,
    reconcile_stats: ReconcileBook,
    cycle_progress: crate::backup::CycleProgressBook,
    self_label: Arc<Mutex<Option<String>>>,
    mdns_peers: Arc<Mutex<HashSet<EndpointId>>>,
    latest_version: crate::update_check::LatestVersion,
    cycle_interval_secs: u64,
    endpoint: Endpoint,
    relay_url: RelayUrl,
    passphrase: SecretString,
    stale_after_secs: u64,
) -> anyhow::Result<()> {
    let state = AppState {
        node_id,
        data_dir,
        buddy_files_dir,
        restore_dir,
        restore_dir_display,
        backup_dir,
        pledge_book,
        bandwidth_book,
        cycle_stats,
        reconcile_stats,
        cycle_progress,
        self_label,
        mdns_peers,
        latest_version,
        cycle_interval_secs,
        endpoint,
        relay_url,
        passphrase,
        stale_after_secs,
        restore_progress: Arc::new(Mutex::new(HashMap::new())),
        started_at: Instant::now(),
    };

    let app = Router::new()
        .route("/", get(index_handler))
        .route("/favicon.svg", get(favicon_handler))
        .route("/mark.svg", get(mark_handler))
        .route("/api/status", get(status_handler))
        .route("/api/buddies/:node_id/files", get(files_handler))
        .route("/api/buddies/:node_id/disk", get(buddy_disk_handler))
        .route("/api/buddies/:node_id/versions", get(versions_handler))
        .route("/api/restore/:node_id", post(restore_handler))
        .route("/api/buddies/:node_id/restore-progress", get(restore_progress_handler))
        .route("/api/restore-version/:node_id", post(restore_version_handler))
        .route("/api/buddies/:node_id/purge", post(purge_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(addr = %bind_addr, "dashboard listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index_handler() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn favicon_handler() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "image/svg+xml")], FAVICON_SVG)
}

async fn mark_handler() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "image/svg+xml")], MARK_SVG)
}

async fn status_handler(State(state): State<AppState>) -> Json<StatusResponse> {
    let pledge_snapshot = { state.pledge_book.lock().unwrap().clone() };
    let cycle_snapshot = { state.cycle_stats.lock().unwrap().clone() };
    let reconcile_snapshot = { state.reconcile_stats.lock().unwrap().clone() };
    let progress_snapshot: HashMap<String, crate::backup::CycleProgress> =
        { state.cycle_progress.lock().unwrap().iter().map(|(k, v)| (k.clone(), v.snapshot())).collect() };

    // Union of "anyone we've received a pledge from" and "anyone we've
    // run a cycle against" — a buddy can appear in only one of the two
    // right after startup, before the other side has happened yet.
    let mut buddy_ids: BTreeSet<String> = pledge_snapshot.keys().cloned().collect();
    buddy_ids.extend(cycle_snapshot.keys().cloned());

    let pledged_out_total_bytes: u64 = pledge_snapshot.values().map(|p| p.pledged_bytes).sum();

    // statvfs is a blocking syscall — cheap, but run it off the async
    // runtime's worker thread like any other blocking call. None (rather
    // than failing the whole request) if the platform or path doesn't
    // support it, so a disk-stats quirk on some host never takes down the
    // rest of the dashboard.
    let disk = {
        let buddy_files_dir = state.buddy_files_dir.clone();
        tokio::task::spawn_blocking(move || fs4::statvfs(&buddy_files_dir))
            .await
            .ok()
            .and_then(|r| r.ok())
            .map(|stats| {
                let total_bytes = stats.total_space();
                let available_bytes = stats.available_space();
                DiskStatus {
                    total_bytes,
                    available_bytes,
                    used_bytes: total_bytes.saturating_sub(available_bytes),
                }
            })
    };

    let mut buddies = Vec::with_capacity(buddy_ids.len());
    for node_id in buddy_ids {
        let pledge = pledge_snapshot.get(&node_id).copied().unwrap_or_default();
        let cycle = cycle_snapshot.get(&node_id).cloned();
        let last_reconcile = reconcile_snapshot.get(&node_id).cloned();

        // Encrypted bytes (comparable to the buddy's own received totals,
        // which are ciphertext too), straight from the index.
        let (sent_files, sent_bytes) = crate::index::get().sent_summary(&node_id).unwrap_or((0, 0));

        let sender_dir = state.buddy_files_dir.join(&node_id);
        // Live files only: the listing also has deleted-but-recoverable
        // entries (kept under .versions/ for restores), which made this
        // read one more than the sender's own count and the reconciliation.
        let received: Vec<_> = receive::list_sender_files(&sender_dir).await.into_iter().filter(|f| !f.deleted).collect();
        let received_files = received.len();
        let received_total_bytes: u64 = received.iter().map(|f| f.size).sum();

        // A buddy only counts as stale once we've actually tried and
        // failed — a brand-new pairing with no cycle yet gets the existing
        // "no cycle yet" pill instead, not a false stale warning.
        let stale = cycle.as_ref().is_some_and(|c| {
            c.last_synced_at
                .map(|at| unix_now().saturating_sub(at) > state.stale_after_secs)
                .unwrap_or(true)
        });

        let in_progress = progress_snapshot.get(&node_id).cloned();
        buddies.push(BuddyStatus {
            label: cycle.as_ref().map(|c| c.label.clone()),
            node_id,
            pledged_bytes: pledge.pledged_bytes,
            received_bytes_counted: pledge.received_bytes,
            received_files,
            received_total_bytes,
            sent_files,
            sent_bytes,
            in_progress,
            last_cycle: cycle,
            stale,
            last_reconcile,
        });
    }

    let bandwidth = *state.bandwidth_book.lock().unwrap();

    let local_backup = match &state.backup_dir {
        Some(dir) => match crate::backup::local_backup_summary(dir).await {
            Ok((file_count, total_bytes)) => Some(LocalBackupStatus { file_count, total_bytes }),
            Err(err) => {
                tracing::warn!(?err, "failed to scan backup dir for dashboard");
                None
            }
        },
        None => None,
    };

    let label = state.self_label.lock().unwrap().clone();
    let latest_version = state.latest_version.lock().unwrap().clone();
    let update_available = latest_version
        .as_deref()
        .is_some_and(|latest| crate::update_check::is_older(env!("CARGO_PKG_VERSION"), latest));

    Json(StatusResponse {
        node_id: state.node_id.clone(),
        label,
        backup_dir: state
            .backup_dir
            .as_ref()
            .map(|p| crate::host_dir(p, "BACKUP_DIR_HOST").unwrap_or_else(|| p.display().to_string())),
        data_dir: state.data_dir.display().to_string(),
        buddy_files_dir: crate::host_dir(&state.buddy_files_dir, "BUDDY_FILES_DIR_HOST")
            .unwrap_or_else(|| state.buddy_files_dir.display().to_string()),
        restore_dir: state.restore_dir_display.clone(),
        version: env!("CARGO_PKG_VERSION"),
        latest_version,
        update_available,
        update_command: if std::env::var("BB_INSTALL_KIND").is_ok_and(|k| k == "image") {
            "docker compose pull && docker compose up -d"
        } else {
            "curl -fsSL https://app.filegarden.net/client/install.sh | bash -s -- --update"
        },
        uptime_secs: state.started_at.elapsed().as_secs(),
        mdns_peers_visible: state.mdns_peers.lock().unwrap().len(),
        cycle_interval_secs: state.cycle_interval_secs,
        local_backup,
        disk,
        pledged_out_total_bytes,
        buddies,
        bandwidth,
    })
}

// Connects to the buddy and asks what they're holding for us — live, over
// the sync protocol, not cached — so the file browser always reflects
// what's actually restorable right now. A buddy with thousands of files
// means a bigger response, not a slower UI: the browser does the
// search/filter client-side over the whole list rather than paging
// through the API, which is simpler and plenty fast at this scale.
async fn files_handler(
    State(state): State<AppState>,
    AxumPath(node_id_str): AxumPath<String>,
) -> impl IntoResponse {
    let buddy_id: EndpointId = match node_id_str.parse() {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, "not a valid Iroh node id".to_string()).into_response(),
    };

    match crate::restore::list_buddy_files(&state.endpoint, &state.relay_url, buddy_id).await {
        Ok(files) => Json(serde_json::json!({ "files": files })).into_response(),
        Err(err) => {
            (StatusCode::BAD_GATEWAY, format!("couldn't reach buddy to list files: {err}")).into_response()
        }
    }
}

// Connects to the buddy and asks for their real disk numbers — live, same
// as files_handler above, not cached — so "keeping each other honest" on
// the dashboard means right now, not whatever was true when the pledge
// was agreed to.
async fn buddy_disk_handler(
    State(state): State<AppState>,
    AxumPath(node_id_str): AxumPath<String>,
) -> impl IntoResponse {
    let buddy_id: EndpointId = match node_id_str.parse() {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, "not a valid Iroh node id".to_string()).into_response(),
    };

    match crate::restore::fetch_buddy_disk_stats(&state.endpoint, &state.relay_url, buddy_id).await {
        Ok((disk, connection)) => Json(BuddyDiskResponse { disk, connection }).into_response(),
        Err(err) => (
            StatusCode::BAD_GATEWAY,
            format!("couldn't reach buddy for disk stats: {err}"),
        )
            .into_response(),
    }
}

// Asks the buddy what backup slots still exist for one path — live, same
// as files_handler, so "what can I recover" always reflects what's
// actually on their disk right now.
async fn versions_handler(
    State(state): State<AppState>,
    AxumPath(node_id_str): AxumPath<String>,
    Query(query): Query<PathQuery>,
) -> impl IntoResponse {
    let buddy_id: EndpointId = match node_id_str.parse() {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, "not a valid Iroh node id".to_string()).into_response(),
    };

    match crate::restore::list_file_versions(&state.endpoint, &state.relay_url, buddy_id, &query.path).await
    {
        Ok(versions) => Json(ListVersionsResponse { versions }).into_response(),
        Err(err) => {
            (StatusCode::BAD_GATEWAY, format!("couldn't reach buddy for version history: {err}"))
                .into_response()
        }
    }
}

/// "Delete permanently" on a deleted file in Browse files: asks the buddy
/// to drop the backup copies it's keeping of it (restore::purge_deleted).
async fn purge_handler(
    State(state): State<AppState>,
    AxumPath(node_id_str): AxumPath<String>,
    Json(body): Json<PathQuery>,
) -> impl IntoResponse {
    let buddy_id: EndpointId = match node_id_str.parse() {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "not a valid Iroh node id" }))).into_response(),
    };
    match crate::restore::purge_deleted(&state.endpoint, &state.relay_url, buddy_id, &body.path).await {
        Ok(()) => {
            tracing::info!(buddy = %node_id_str, path = %body.path, "deleted a file's backup copies permanently");
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        Err(err) => {
            tracing::warn!(buddy = %node_id_str, path = %body.path, error = %err, "delete permanently failed");
            (StatusCode::BAD_GATEWAY, Json(serde_json::json!({ "error": err.to_string() }))).into_response()
        }
    }
}

#[derive(Serialize)]
struct ListVersionsResponse {
    versions: Vec<crate::protocol::VersionEntry>,
}

// Restores one backup slot of one file — see restore::restore_version for
// where it ends up on disk (suffixed, alongside a normal restore, never
// overwriting it).
async fn restore_version_handler(
    State(state): State<AppState>,
    AxumPath(node_id_str): AxumPath<String>,
    Json(body): Json<RestoreVersionRequest>,
) -> impl IntoResponse {
    let buddy_id: EndpointId = match node_id_str.parse() {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, "not a valid Iroh node id".to_string()).into_response(),
    };

    let restore_dir = state.restore_dir.join(&node_id_str);
    if let Err(err) = tokio::fs::create_dir_all(&restore_dir).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("couldn't create restore directory: {err}"))
            .into_response();
    }

    match crate::restore::restore_version(
        &state.endpoint,
        &state.relay_url,
        &state.passphrase,
        buddy_id,
        &restore_dir,
        &body.path,
        body.version,
    )
    .await
    {
        Ok(stats) => {
            tracing::info!(
                buddy = %node_id_str,
                files = stats.files_restored,
                bytes = stats.bytes_restored,
                duration_ms = stats.duration_ms,
                dir = %format!("{}/{}", state.restore_dir_display, node_id_str),
                "restore from the dashboard complete"
            );
            if let Some(traffic) = stats.traffic {
                crate::bandwidth::record_split(&state.data_dir, &state.bandwidth_book, traffic).await;
            }
            Json(RestoreResponse {
                restored_files: stats.files_restored,
                dir: format!("{}/{}", state.restore_dir_display, node_id_str),
                bytes_restored: stats.bytes_restored,
                duration_ms: stats.duration_ms,
                connection: stats.connection,
            })
            .into_response()
        }
        Err(err) => {
            tracing::warn!(buddy = %node_id_str, error = %err, "restore from the dashboard failed");
            (StatusCode::BAD_GATEWAY, format!("restore failed: {err}")).into_response()
        }
    }
}

// Pulls files that buddy currently has stored for us and writes them
// under RESTORE_DIR/<their node id>/ — a fixed, predictable
// location (separate per buddy, so restoring from two buddies in a row
// can't clobber each other), unlike the `restore` CLI subcommand which
// takes an explicit destination. An empty/absent `paths` in the request
// body means "restore everything"; specific paths (from the file
// browser) mean just those. Either way, this always resolves against a
// fresh file list first (rather than trusting an empty `paths` straight
// to restore::run_restore, or specific paths straight to
// restore::restore_selected) so it can: skip deleted-but-recoverable
// entries up front instead of wasting a round trip on a Get that can
// only fail, and know the total file count/bytes before starting, which
// is what makes restore-progress polling possible (see
// restore_progress_handler below).
async fn restore_handler(
    State(state): State<AppState>,
    AxumPath(node_id_str): AxumPath<String>,
    body: Option<Json<RestoreRequest>>,
) -> impl IntoResponse {
    let buddy_id: EndpointId = match node_id_str.parse() {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, "not a valid Iroh node id".to_string()).into_response(),
    };
    let requested = body.map(|Json(b)| b.paths).unwrap_or_default();

    let restore_dir = state.restore_dir.join(&node_id_str);
    if let Err(err) = tokio::fs::create_dir_all(&restore_dir).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("couldn't create restore directory: {err}"))
            .into_response();
    }

    let all_files = match crate::restore::list_buddy_files(&state.endpoint, &state.relay_url, buddy_id).await {
        Ok(files) => files,
        Err(err) => {
            return (StatusCode::BAD_GATEWAY, format!("couldn't reach buddy to list files: {err}"))
                .into_response();
        }
    };
    let wanted: std::collections::HashSet<&str> = requested.iter().map(|s| s.as_str()).collect();
    let selected: Vec<ListEntry> = all_files
        .into_iter()
        .filter(|f| !f.deleted && (requested.is_empty() || wanted.contains(f.path.as_str())))
        .collect();
    let total_bytes: u64 = selected.iter().map(|f| f.size).sum();
    let paths: Vec<String> = selected.into_iter().map(|f| f.path).collect();

    let progress: crate::restore::ProgressHandle = Arc::new(Mutex::new(crate::restore::RestoreProgress {
        total_files: paths.len(),
        total_bytes,
        started_unix: unix_now(),
        ..Default::default()
    }));
    state.restore_progress.lock().unwrap().insert(node_id_str.clone(), progress.clone());

    let result = crate::restore::restore_selected(
        &state.endpoint,
        &state.relay_url,
        &state.passphrase,
        buddy_id,
        &restore_dir,
        &paths,
        Some(progress.clone()),
    )
    .await;

    if let Ok(mut g) = progress.lock() {
        g.done = true;
        g.current_path = None;
        if let Err(err) = &result {
            g.error = Some(err.to_string());
        }
    }

    match result {
        Ok(stats) => {
            tracing::info!(
                buddy = %node_id_str,
                files = stats.files_restored,
                bytes = stats.bytes_restored,
                duration_ms = stats.duration_ms,
                dir = %format!("{}/{}", state.restore_dir_display, node_id_str),
                "restore from the dashboard complete"
            );
            if let Some(traffic) = stats.traffic {
                crate::bandwidth::record_split(&state.data_dir, &state.bandwidth_book, traffic).await;
            }
            Json(RestoreResponse {
                restored_files: stats.files_restored,
                dir: format!("{}/{}", state.restore_dir_display, node_id_str),
                bytes_restored: stats.bytes_restored,
                duration_ms: stats.duration_ms,
                connection: stats.connection,
            })
            .into_response()
        }
        Err(err) => {
            tracing::warn!(buddy = %node_id_str, error = %err, "restore from the dashboard failed");
            (StatusCode::BAD_GATEWAY, format!("restore failed: {err}")).into_response()
        }
    }
}

// Polled by the browser while a restore's own POST is still in flight
// (see doRestore's onProgress in the JS below). `{"active": false}` when
// nothing's ever been kicked off for this buddy; otherwise the latest
// restore's progress, which stays queryable (with `done: true`) after it
// finishes too, so a poll that lands just after completion still gets a
// real answer instead of a stale "in progress".
async fn restore_progress_handler(
    State(state): State<AppState>,
    AxumPath(node_id_str): AxumPath<String>,
) -> impl IntoResponse {
    let book = state.restore_progress.lock().unwrap();
    match book.get(&node_id_str) {
        Some(handle) => {
            let snapshot = handle.lock().unwrap().clone();
            Json(serde_json::json!({ "active": true, "progress": snapshot })).into_response()
        }
        None => Json(serde_json::json!({ "active": false })).into_response(),
    }
}

// A single self-contained page — no build step, no bundler, consistent
// with how small this client otherwise is. Polls /api/status every 5s and
// re-renders; the "Restore now" button posts to /api/restore/<id> and
// shows the result (or error) inline rather than navigating away.
const INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Backup Buddies — this device</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>
  :root {
    --bg: #0f1115; --surface: #171a21; --border: #2a2e38; --text: #e8e9ec;
    --text-muted: #9499a6; --accent: #4f8cff; --accent-text: #0f1115;
    --danger: #ff6b6b; --ok: #4caf7d; --radius: 10px;
    /* Echoes the blue→teal gradient in /mark.svg, matching the main site's
       apps/web/style.css so the client's own dashboard reads as the same
       brand instead of flat solid blue. */
    --accent-grad: linear-gradient(135deg, #2ec5ff, #42e6a4);
    --accent-glow: rgba(79, 140, 255, 0.35);
    --ease: cubic-bezier(0.2, 0.7, 0.3, 1);
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    background:
      radial-gradient(900px 480px at 12% -10%, rgba(46, 197, 255, 0.08), transparent 60%),
      radial-gradient(800px 420px at 100% 0%, rgba(66, 230, 164, 0.06), transparent 55%),
      var(--bg);
    background-attachment: fixed;
    color: var(--text); line-height: 1.5;
  }
  header { padding: 1.25rem 1.5rem; border-bottom: 1px solid var(--border); }
  header .title-row { display: flex; align-items: center; gap: 0.6rem; }
  header .title-row img { width: 26px; height: 26px; display: block; transition: transform 0.25s var(--ease); }
  header .title-row:hover img { transform: rotate(-8deg) scale(1.08); }
  header h1 {
    font-size: 1.1rem; margin: 0;
    background: var(--accent-grad); -webkit-background-clip: text; background-clip: text; color: transparent;
  }
  header .sub { color: var(--text-muted); font-size: 0.85rem; margin-top: 0.25rem; }
  main { max-width: 1200px; margin: 0 auto; padding: 1.5rem; }
  /* This Device / Disk / Bandwidth on the left, buddy cards on the right —
     a fixed two-column split (not a height-balanced masonry one) since
     which side a card belongs on is decided by what it is, not by what
     fits where. Mirrors the web dashboard's own left/right grouping. */
  .device-grid { display: flex; gap: 1.25rem; align-items: flex-start; }
  .device-grid-left { flex: 1; min-width: 0; }
  .device-grid-right { flex: 1.3; min-width: 0; }
  @media (max-width: 860px) {
    .device-grid { flex-direction: column; }
  }
  .card {
    position: relative; overflow: hidden;
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
    padding: 1.25rem 1.5rem; margin-bottom: 1.25rem;
    transition: border-color 0.2s var(--ease);
  }
  .card::before {
    content: ""; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: var(--accent-grad); opacity: 0.6;
  }
  .card:hover { border-color: #394055; }
  .card h2 { margin: 0 0 0.75rem; font-size: 1rem; }
  .row { display: flex; justify-content: space-between; gap: 1rem; flex-wrap: wrap; }
  .pill {
    display: inline-block; padding: 0.15rem 0.55rem; border-radius: 999px;
    font-size: 0.75rem; font-weight: 600;
  }
  .pill-ok { background: rgba(76,175,125,0.15); color: var(--ok); }
  .pill-err { background: rgba(255,107,107,0.15); color: var(--danger); }
  .pill-pending { background: rgba(148,153,166,0.15); color: var(--text-muted); }
  .pill-warn { background: rgba(240,180,60,0.18); color: #f0b43c; }
  .update-cmd { display: block; margin-top: 0.35rem; font-size: 0.72rem; user-select: all; word-break: break-all; }
  .muted { color: var(--text-muted); font-size: 0.85rem; }
  .bar-track { background: #11141a; border-radius: 6px; height: 6px; overflow: hidden; margin-top: 0.4rem; }
  .bar-fill { background: var(--accent-grad); height: 100%; transition: width 0.3s var(--ease); }
  .bar-fill-warn { background: var(--danger); }
  .disk-stats { display: flex; gap: 1.5rem; flex-wrap: wrap; margin-top: 0.75rem; }
  .disk-stats .stat .label { color: var(--text-muted); font-size: 0.78rem; }
  .disk-stats .stat .value { font-size: 1rem; font-weight: 600; margin-top: 0.1rem; }
  .disk-warning {
    margin-top: 0.75rem; padding: 0.6rem 0.8rem; border-radius: 8px; font-size: 0.82rem;
    background: rgba(255,107,107,0.12); color: var(--danger);
  }
  .buddy-disk-recheck { margin-left: 0.4rem; padding: 0.15rem 0.5rem; font-size: 0.72rem; }
  button {
    background: var(--accent-grad); color: var(--accent-text); border: none; border-radius: 8px;
    padding: 0.45rem 0.9rem; font-size: 0.85rem; font-weight: 600; cursor: pointer;
    transition: transform 0.15s var(--ease), box-shadow 0.15s var(--ease), opacity 0.15s var(--ease);
  }
  button:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 6px 20px -6px var(--accent-glow); }
  button:active:not(:disabled) { transform: translateY(0); }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  .restore-result { font-size: 0.8rem; margin-top: 0.5rem; }
  code { background: #11141a; padding: 0.1rem 0.35rem; border-radius: 4px; font-size: 0.85em; }
  #empty { color: var(--text-muted); }
  button.secondary {
    background: var(--surface); color: var(--text); border: 1px solid var(--border); box-shadow: none;
  }
  button.secondary:hover:not(:disabled) {
    border-color: var(--accent); background: rgba(79, 140, 255, 0.08); box-shadow: none;
  }
  .modal-backdrop {
    display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.6);
    align-items: center; justify-content: center; padding: 2rem; z-index: 10;
  }
  .modal-backdrop.open { display: flex; }
  .modal {
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
    width: 100%; max-width: 700px; max-height: 85vh; display: flex; flex-direction: column;
    padding: 1.25rem 1.5rem;
  }
  .modal-header { display: flex; justify-content: space-between; align-items: center; gap: 1rem; }
  .modal-header h2 { margin: 0; font-size: 1rem; }
  .modal-header button { padding: 0.25rem 0.6rem; }
  .modal-search { margin-top: 0.9rem; }
  .modal-search input {
    width: 100%; background: #11141a; border: 1px solid var(--border); border-radius: 8px;
    color: var(--text); padding: 0.5rem 0.7rem; font-size: 0.85rem;
    transition: border-color 0.15s var(--ease), box-shadow 0.15s var(--ease);
  }
  .modal-search input:focus {
    outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow);
  }
  .browse-breadcrumb {
    display: flex; align-items: center; gap: 0.3rem; margin-top: 0.6rem;
    font-size: 0.8rem; flex-wrap: wrap;
  }
  .browse-breadcrumb a { color: var(--accent); text-decoration: none; }
  .browse-breadcrumb a:hover { text-decoration: underline; }
  .browse-breadcrumb .crumb-sep { color: var(--text-muted); }
  .file-row .file-icon { width: 1.1em; text-align: center; flex-shrink: 0; }
  .file-row .folder-link { color: var(--text); font-weight: 600; }
  .modal-actions { display: flex; align-items: center; justify-content: space-between; gap: 1rem; margin-top: 0.75rem; }
  .modal-actions .muted { font-size: 0.78rem; }
  .file-list { overflow-y: auto; margin-top: 0.75rem; border-top: 1px solid var(--border); }
  .file-row {
    display: flex; align-items: center; gap: 0.6rem; padding: 0.5rem 0.1rem;
    border-bottom: 1px solid var(--border); font-size: 0.82rem;
    transition: background-color 0.15s var(--ease);
  }
  .file-row:hover { background-color: rgba(255, 255, 255, 0.025); }
  .file-row .path { flex: 1; word-break: break-all; }
  .file-row .size { color: var(--text-muted); white-space: nowrap; }
  .file-row-deleted .path { color: var(--text-muted); font-style: italic; }
  .file-row button { padding: 0.25rem 0.6rem; font-size: 0.75rem; }
  .file-history {
    padding: 0.4rem 0.6rem 0.6rem 2.3rem; font-size: 0.78rem; color: var(--text-muted);
    border-bottom: 1px solid var(--border); background: rgba(255,255,255,0.02);
  }
  .version-row { display: flex; justify-content: space-between; align-items: center; gap: 0.6rem; padding: 0.25rem 0; }
  .version-row button { padding: 0.2rem 0.55rem; font-size: 0.72rem; flex-shrink: 0; }
  .modal-status { font-size: 0.8rem; margin-top: 0.6rem; }
  .modal-footer { margin-top: 0.75rem; padding-top: 0.75rem; border-top: 1px solid var(--border); }
</style>
</head>
<body>
<header>
  <div class="title-row">
    <img src="/mark.svg" alt="">
    <h1>Backup Buddies</h1>
  </div>
  <div class="sub">This device: <span id="device-label">…</span> <code id="node-id" class="muted"></code> · backing up <code id="backup-dir">…</code></div>
</header>
<main>
<div class="device-grid">
<div class="device-grid-left">
  <div class="card" id="device-card">
    <h2>This Device</h2>
    <div class="disk-stats">
      <div class="stat">
        <div class="label">Version</div>
        <div class="value" id="device-version">…</div>
        <div id="device-update" style="display:none; margin-top:0.3rem;">
          <span class="pill" id="device-update-pill"></span>
          <code class="update-cmd muted" id="device-update-cmd" style="display:none;"></code>
        </div>
      </div>
      <div class="stat">
        <div class="label">Uptime</div>
        <div class="value" id="device-uptime">…</div>
      </div>
      <div class="stat" id="local-files-stat" style="display:none;">
        <div class="label">Local files</div>
        <div class="value" id="local-files-count">…</div>
      </div>
      <div class="stat" id="local-size-stat" style="display:none;">
        <div class="label">Local size</div>
        <div class="value" id="local-files-size">…</div>
      </div>
      <div class="stat">
        <div class="label">Discovery (LAN)</div>
        <div class="value" id="device-mdns-peers">…</div>
      </div>
      <div class="stat">
        <div class="label">Rescan interval</div>
        <div class="value" id="device-cycle-interval">…</div>
      </div>
    </div>
  </div>
  <div class="card" id="disk-card" style="display:none;">
    <h2>Disk</h2>
    <div class="muted">Buddy files: <code id="buddy-files-dir">…</code></div>
    <div class="disk-stats">
      <div class="stat">
        <div class="label">Used</div>
        <div class="value" id="disk-used">…</div>
      </div>
      <div class="stat">
        <div class="label">Free</div>
        <div class="value" id="disk-free">…</div>
      </div>
      <div class="stat">
        <div class="label">Total</div>
        <div class="value" id="disk-total">…</div>
      </div>
      <div class="stat">
        <div class="label">Pledged out</div>
        <div class="value" id="disk-pledged">…</div>
      </div>
    </div>
    <div class="bar-track"><div class="bar-fill" id="disk-bar" style="width:0%"></div></div>
    <div class="disk-warning" id="disk-warning" style="display:none;"></div>
  </div>
  <div class="card" id="bandwidth-card">
    <h2>Bandwidth</h2>
    <div class="muted">Lifetime, across every backup, restore, and buddy request this device has handled.</div>
    <div class="disk-stats">
      <div class="stat">
        <div class="label">Via relay</div>
        <div class="value" id="bw-relay">…</div>
      </div>
      <div class="stat">
        <div class="label">Direct (peer-to-peer)</div>
        <div class="value" id="bw-direct">…</div>
      </div>
      <div class="stat">
        <div class="label">Total</div>
        <div class="value" id="bw-total">…</div>
      </div>
    </div>
    <div class="bar-track"><div class="bar-fill" id="bw-bar" style="width:0%"></div></div>
    <div class="muted" style="margin-top:0.4rem; font-size:0.78rem;" id="bw-note"></div>
  </div>
</div>
<div class="device-grid-right">
  <div id="empty" class="card" style="display:none;">No buddies seen yet — waiting on the first poll of the API.</div>
  <div id="buddies"></div>
</div>
</div>
</main>

<div class="modal-backdrop" id="browse-modal">
  <div class="modal">
    <div class="modal-header">
      <h2 id="browse-title">Files</h2>
      <button class="secondary" id="browse-close">Close</button>
    </div>
    <div class="modal-search">
      <input type="text" id="browse-search" placeholder="Search by path…">
    </div>
    <div class="browse-breadcrumb" id="browse-breadcrumb"></div>
    <div class="modal-actions">
      <label class="muted"><input type="checkbox" id="browse-select-all"> select all</label>
      <span class="muted" id="browse-count"></span>
    </div>
    <div class="file-list" id="browse-list"></div>
    <div class="modal-footer">
      <button id="browse-restore-selected" disabled>Restore selected</button>
      <button class="secondary" id="browse-restore-all">Restore all</button>
      <div class="restore-result" id="browse-result"></div>
    </div>
  </div>
</div>

<script>
function fmtBytes(n) {
  if (n === 0) return "0 B";
  const u = ["B","KB","MB","GB","TB"];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return (n / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + " " + u[i];
}
function fmtAgo(unixSecs) {
  const secs = Math.max(0, Math.floor(Date.now() / 1000) - unixSecs);
  if (secs < 60) return secs + "s ago";
  if (secs < 3600) return Math.floor(secs / 60) + "m ago";
  return Math.floor(secs / 3600) + "h ago";
}
// "5m", "3h 12m", "2d 04h" — coarse, same spirit as fmtEta: nobody needs
// second-level precision on how long a process has been up.
function fmtUptime(secs) {
  secs = Math.max(0, Math.floor(secs));
  const mins = Math.floor(secs / 60);
  if (mins < 60) return mins + "m";
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return hrs + "h " + String(mins % 60).padStart(2, "0") + "m";
  const days = Math.floor(hrs / 24);
  return days + "d " + String(hrs % 24).padStart(2, "0") + "h";
}

// Transfer rate from raw bytes/duration rather than storing a precomputed
// rate anywhere — these are the only two numbers worth persisting, a rate
// is just how they're read. Null when duration is too small to be a
// meaningful denominator (near-instant transfers of a tiny file).
function fmtRate(bytes, ms) {
  if (!ms || ms < 50) return null;
  return fmtBytes(bytes / (ms / 1000)) + "/s";
}

// "45s" / "3m 12s" / "2h 05m" — coarse on purpose, an ETA that claims
// second-level precision over a multi-hour restore is just noise.
function fmtEta(seconds) {
  seconds = Math.max(0, Math.round(seconds));
  if (seconds < 60) return seconds + "s";
  const mins = Math.floor(seconds / 60);
  if (mins < 60) return mins + "m " + (seconds % 60) + "s";
  const hrs = Math.floor(mins / 60);
  return hrs + "h " + String(mins % 60).padStart(2, "0") + "m";
}

// Turns one /restore-progress poll into the one line shown while a
// restore is running. File-count progress (N of M) is always shown since
// it's always known up front; byte progress and an ETA are layered on
// top only once there's enough signal for them to mean anything — a
// rate computed over under a second, or applied to a transfer that's
// basically already done, is more misleading than no estimate at all.
function describeRestoreProgress(p) {
  let line = "Restoring " + p.completed_files + " of " + p.total_files + " file(s)";
  if (p.total_bytes > 0) {
    const pct = Math.min(100, Math.round((p.bytes_done / p.total_bytes) * 100));
    line += " — " + fmtBytes(p.bytes_done) + " of " + fmtBytes(p.total_bytes) + " (" + pct + "%)";

    const elapsed = p.started_unix ? Date.now() / 1000 - p.started_unix : 0;
    const remaining = p.total_bytes - p.bytes_done;
    if (elapsed > 1.5 && remaining > 0) {
      const rate = p.bytes_done / elapsed; // bytes/sec — the only part of
      // the "math equation": remaining ÷ rate so far, same idea as any
      // download ETA, not a precise forecast of a connection that can
      // speed up or stall.
      if (rate > 0) line += " — ~" + fmtEta(remaining / rate) + " remaining at " + fmtBytes(rate) + "/s";
    }
  }
  if (p.current_path) line += " — " + p.current_path;
  return line;
}

function escapeHtml(text) {
  return String(text).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

// One line + bar fraction for a backup cycle that's running right now
// (status.buddies[].in_progress — see backup.rs's CycleProgress), so a
// long first backup shows how far along it is instead of "no cycle yet".
function describeCycleProgress(p) {
  const n = (x) => Number(x).toLocaleString();
  const curFrac = p.current_size > 0 ? Math.min(1, p.current_done / p.current_size) : 0;
  const curSize = p.current_size > 0 ? " (" + fmtBytes(p.current_done) + " of " + fmtBytes(p.current_size) + ")" : "";
  if (p.phase === "checking") {
    const frac = p.files_total > 0 ? (p.files_checked + curFrac) / p.files_total : 0;
    return {
      frac,
      line: "Checking for new or changed files — " + n(p.files_checked) + " of " + n(p.files_total) +
        (p.current_path ? " — reading " + p.current_path + curSize : ""),
    };
  }
  if (p.phase === "deleting") {
    const frac = p.files_to_delete > 0 ? p.files_deleted / p.files_to_delete : 1;
    return {
      frac,
      line: "Telling your buddy about deleted files — " + n(p.files_deleted) + " of " + n(p.files_to_delete),
    };
  }
  const done = Math.min(p.bytes_to_send, p.bytes_sent + p.current_done);
  const frac = p.bytes_to_send > 0 ? done / p.bytes_to_send : (p.files_to_send > 0 ? p.files_sent / p.files_to_send : 0);
  let line = "Backing up " + n(Math.min(p.files_sent + 1, p.files_to_send)) + " of " + n(p.files_to_send) + " file(s)";
  if (p.bytes_to_send > 0) {
    line += " — " + fmtBytes(done) + " of " + fmtBytes(p.bytes_to_send) + " (" + Math.floor(frac * 100) + "%)";
    const elapsed = p.sending_started_unix ? p.now_unix - p.sending_started_unix : 0;
    const remaining = p.bytes_to_send - done;
    // Bytes a resumed upload found already on the buddy weren't sent
    // this cycle; leave them out of the speed.
    const sentNow = done - (p.bytes_skipped || 0);
    if (elapsed >= 5 && sentNow > 0 && remaining > 0) {
      const rate = sentNow / elapsed;
      line += " — ~" + fmtEta(remaining / rate) + " left at " + fmtBytes(rate) + "/s";
    }
  }
  if (p.current_path) line += " — " + p.current_path + curSize;
  return { frac, line };
}

// "direct, 14ms" / "via relay, 80ms" / "connecting…" — iroh tries a
// direct peer-to-peer path first and falls back to relaying through
// relay.filegarden.net when NAT traversal doesn't work out; this is the
// one line on the dashboard that says which one actually happened.
function fmtConnection(connection) {
  if (!connection) return "";
  const kind =
    connection.path === "direct" ? "direct" : connection.path === "relay" ? "via relay" : "connecting…";
  const rtt = connection.rtt_ms != null ? ", " + connection.rtt_ms + "ms" : "";
  return kind + rtt;
}

// Shared by every "a restore just happened" result line (the plain
// restore button, restore-selected, restore-all, and the file browser's
// per-row restore) so the transfer-metrics phrasing stays identical
// everywhere it shows up.
function describeRestoreResult(body) {
  // Restore asks the buddy for everything it's holding from this device —
  // zero means it has nothing live from us (e.g. this device has never
  // sent them anything), not that something failed.
  if (body.restored_files === 0) {
    let msg = "Nothing to restore — this buddy isn't holding any of this device's files.";
    if (body.connection) msg += " · " + fmtConnection(body.connection);
    return msg;
  }
  let msg = "Restored " + body.restored_files + " file(s) to " + body.dir;
  const rate = fmtRate(body.bytes_restored, body.duration_ms);
  if (rate) {
    msg += " — " + fmtBytes(body.bytes_restored) + " in " + (body.duration_ms / 1000).toFixed(1) + "s (" + rate + ")";
  }
  if (body.connection) msg += " · " + fmtConnection(body.connection);
  return msg;
}

// --- Buddy disk checks (keeping each other honest) ------------------------
// A buddy's pledge is just a number agreed over the API — this asks them
// live, over the sync protocol, what their disk actually looks like right
// now. Auto-rechecked at most once an hour per buddy (buddyDiskLastFetched
// tracks when each one was last asked) even though the card re-renders
// every 5s along with the rest of the status poll — that poll is what
// notices a check is due, not what drives the check's own frequency. The
// "Recheck" button bypasses the hourly floor for an on-demand refresh.
const BUDDY_DISK_RECHECK_MS = 60 * 60 * 1000; // once an hour
const buddyDiskCache = new Map(); // nodeId -> {text, color}
const buddyDiskLastFetched = new Map(); // nodeId -> ms timestamp of last fetch *attempt*

function formatDiskSummary(stats) {
  if (!stats || stats.total_bytes === 0) {
    return { text: "unknown (couldn't read their disk stats)", color: "var(--text-muted)" };
  }
  const overCommitted = stats.pledged_out_total_bytes > stats.available_bytes;
  let text =
    fmtBytes(stats.available_bytes) + " free of " + fmtBytes(stats.total_bytes) +
    " — pledged out to buddies: " + fmtBytes(stats.pledged_out_total_bytes) +
    (overCommitted ? " (more than they have free!)" : "");
  if (stats.connection) text += " · " + fmtConnection(stats.connection);
  return { text, color: overCommitted ? "var(--danger)" : "var(--text-muted)" };
}

function applyBuddyDisk(nodeId, root = document) {
  const el = root.querySelector('.buddy-disk[data-node-id="' + CSS.escape(nodeId) + '"]');
  if (!el) return;
  const cached = buddyDiskCache.get(nodeId);
  if (!cached) {
    el.textContent = "checking…";
    el.style.color = "";
    return;
  }
  el.textContent = cached.text;
  el.style.color = cached.color;
}

async function fetchBuddyDisk(nodeId) {
  try {
    const res = await fetch("/api/buddies/" + encodeURIComponent(nodeId) + "/disk");
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
    buddyDiskCache.set(nodeId, formatDiskSummary(data));
  } catch (err) {
    buddyDiskCache.set(nodeId, { text: "couldn't reach them (" + err.message + ")", color: "var(--danger)" });
  }
  applyBuddyDisk(nodeId);
}

// Kicks off a restore (POST /api/restore) and, if onProgress is given,
// polls GET /restore-progress on a separate interval the whole time
// that POST is in flight — the two are independent requests precisely
// so a restore that takes a while doesn't leave onProgress's caller
// with nothing to show but a frozen "Restoring…" until it's done. The
// poller is stopped (not left running) once the POST itself resolves
// either way, success or failure.
async function doRestore(nodeId, paths, onProgress) {
  let timer = null;
  // A progress poll can still be in flight when the restore itself
  // finishes; its late reply must not overwrite the final result with
  // "Restoring…" again (and leave the button disabled). clearInterval only
  // stops *future* polls, so this flag drops replies from the last one.
  let finished = false;
  if (onProgress) {
    timer = setInterval(async () => {
      try {
        const res = await fetch("/api/buddies/" + encodeURIComponent(nodeId) + "/restore-progress");
        const body = await res.json().catch(() => ({}));
        if (!finished && body && body.active) onProgress(body.progress);
      } catch {
        // a missed poll just means one stale tick of progress text —
        // not worth surfacing as an error on top of the restore itself
      }
    }, 700);
  }
  try {
    const res = await fetch("/api/restore/" + encodeURIComponent(nodeId), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ paths: paths || [] }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || ("HTTP " + res.status));
    return body;
  } finally {
    finished = true;
    if (timer) clearInterval(timer);
  }
}

// Per-buddy restore status, kept outside the card itself: refresh()
// rebuilds every buddy card from scratch every few seconds, so anything
// written only into the card's DOM (the "Restored N file(s)…" line, or the
// live progress while a restore runs) would vanish on the next refresh.
// Same idea as buddyDiskCache. Survives until the page is reloaded or
// another restore from that buddy replaces it.
const restoreStatus = new Map(); // nodeId -> { text, color, running }

function setRestoreStatus(nodeId, status) {
  restoreStatus.set(nodeId, status);
  applyRestoreStatus(nodeId, document);
}

// `root` is the card being built (not yet in the page) or `document`.
function applyRestoreStatus(nodeId, root) {
  const status = restoreStatus.get(nodeId);
  const sel = '[data-node-id="' + CSS.escape(nodeId) + '"]';
  const resultEl = root.querySelector(".restore-result" + sel);
  const btn = root.querySelector(".restore-btn" + sel);
  if (btn) btn.disabled = Boolean(status && status.running);
  if (!resultEl) return;
  resultEl.textContent = status ? status.text : "";
  resultEl.style.color = status && status.color ? status.color : "";
}

async function restoreNow(nodeId) {
  setRestoreStatus(nodeId, { text: "Restoring…", running: true });
  try {
    const body = await doRestore(nodeId, [], (p) => {
      setRestoreStatus(nodeId, { text: describeRestoreProgress(p), running: true });
    });
    setRestoreStatus(nodeId, { text: describeRestoreResult(body), color: "var(--ok)", running: false });
  } catch (err) {
    setRestoreStatus(nodeId, { text: "Restore failed: " + err.message, color: "var(--danger)", running: false });
  }
}

// --- File browser modal ---------------------------------------------------
// Fetches a buddy's file list once when opened (a flat [{path, size}]
// list — that's all the sync protocol has ever reported, there's no real
// directory listing on the wire) and builds a folder tree from it
// client-side, so browsing feels like a normal folder view: one level at
// a time, click into a folder, breadcrumb back out. Typing in the search
// box switches to a flat, full-path-matching view across every file
// instead — search and "browse one folder" want different shapes, and
// trying to make one view do both gets confusing fast.
const browseState = {
  nodeId: null,
  label: "",
  files: [], // flat, as returned by the server
  tree: null, // built from files by buildFileTree()
  currentPath: "", // "" = root; "testdir"; "a/b"; ... — folder currently open
  selected: new Set(),
};

const browseModal = document.getElementById("browse-modal");
const browseTitle = document.getElementById("browse-title");
const browseSearch = document.getElementById("browse-search");
const browseBreadcrumb = document.getElementById("browse-breadcrumb");
const browseList = document.getElementById("browse-list");
const browseCount = document.getElementById("browse-count");
const browseSelectAll = document.getElementById("browse-select-all");
const browseRestoreSelected = document.getElementById("browse-restore-selected");
const browseRestoreAll = document.getElementById("browse-restore-all");
const browseResult = document.getElementById("browse-result");

function closeBrowseModal() {
  browseModal.classList.remove("open");
  browseState.nodeId = null;
  browseState.files = [];
  browseState.tree = null;
  browseState.currentPath = "";
  browseState.selected.clear();
}

// { dirs: Map<name, node>, items: [{name, path, size}] } per directory.
function buildFileTree(files) {
  const root = { dirs: new Map(), items: [] };
  for (const f of files) {
    const parts = f.path.split("/").filter(Boolean);
    let node = root;
    for (let i = 0; i < parts.length - 1; i++) {
      const name = parts[i];
      if (!node.dirs.has(name)) node.dirs.set(name, { dirs: new Map(), items: [] });
      node = node.dirs.get(name);
    }
    const name = parts.length > 0 ? parts[parts.length - 1] : f.path;
    node.items.push({ name, path: f.path, size: f.size, deleted: !!f.deleted });
  }
  return root;
}

function nodeAtPath(path) {
  let node = browseState.tree;
  if (!node || !path) return node;
  for (const part of path.split("/")) {
    node = node.dirs.get(part);
    if (!node) return null;
  }
  return node;
}

// Every file path recursively under a tree node — what a folder's
// checkbox or "Restore" button acts on.
// Deleted entries are left out here on purpose — they have no checkbox
// (see makeFileRow) and nothing live to restore the normal way, so
// "select all" / bulk restore should skip over them rather than silently
// failing to restore a file the person never checked themselves.
function collectPaths(node) {
  let paths = node.items.filter((it) => !it.deleted).map((it) => it.path);
  for (const child of node.dirs.values()) paths = paths.concat(collectPaths(child));
  return paths;
}

function renderBreadcrumb() {
  const parts = browseState.currentPath ? browseState.currentPath.split("/") : [];
  browseBreadcrumb.innerHTML = "";

  const rootLink = document.createElement("a");
  rootLink.href = "javascript:void(0)";
  rootLink.textContent = "Home";
  rootLink.addEventListener("click", (ev) => {
    ev.preventDefault();
    browseState.currentPath = "";
    renderBrowseView();
  });
  browseBreadcrumb.appendChild(rootLink);

  let built = "";
  for (const part of parts) {
    built = built ? built + "/" + part : part;
    const sep = document.createElement("span");
    sep.className = "crumb-sep";
    sep.textContent = "/";
    browseBreadcrumb.appendChild(sep);

    const link = document.createElement("a");
    link.href = "javascript:void(0)";
    link.textContent = part;
    const target = built;
    link.addEventListener("click", (ev) => {
      ev.preventDefault();
      browseState.currentPath = target;
      renderBrowseView();
    });
    browseBreadcrumb.appendChild(link);
  }
}

// Returns a fragment of [row, history-panel] rather than just the row, so
// every existing call site (`browseList.appendChild(makeFileRow(item))`)
// keeps working unchanged — appending a fragment appends both children in
// order. The history panel stays empty and hidden until "History" is
// clicked, so opening the browser doesn't fire a versions request per file.
// A `deleted` item has no live file left — just a backup slot under
// .versions/ (see collect_deleted in receive.rs). It can't be restored the
// normal way (there's nothing live to fetch), so it gets no checkbox and
// no plain "Restore" button, only "History" to pick a surviving version —
// same path an overwritten file's older versions already go through.
function makeFileRow(item) {
  const frag = document.createDocumentFragment();
  const row = document.createElement("div");
  row.className = "file-row" + (item.deleted ? " file-row-deleted" : "");
  row.innerHTML = `
    ${item.deleted ? "" : '<input type="checkbox" class="file-pick">'}
    <span class="file-icon">${item.deleted ? "🗑️" : "📄"}</span>
    <span class="path">${escapeHtml(item.name)}${item.deleted ? " (deleted — recoverable)" : ""}</span>
    <span class="size">${fmtBytes(item.size)}</span>
    ${item.deleted ? "" : '<button class="secondary file-restore-one">Restore</button>'}
    <button class="secondary file-history-toggle">History</button>
    ${item.deleted ? '<button class="secondary file-purge" style="color: var(--danger);">Delete permanently</button>' : ""}
  `;
  const history = document.createElement("div");
  history.className = "file-history";
  history.style.display = "none";

  const checkbox = row.querySelector(".file-pick");
  if (checkbox) {
    checkbox.checked = browseState.selected.has(item.path);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) browseState.selected.add(item.path);
      else browseState.selected.delete(item.path);
      updateSelectedControls();
    });
  }
  row.querySelector(".file-restore-one")?.addEventListener("click", async (ev) => {
    const btn = ev.target;
    btn.disabled = true;
    browseResult.textContent = "Restoring " + item.path + "…";
    browseResult.style.color = "";
    try {
      const body = await doRestore(browseState.nodeId, [item.path], (p) => {
        browseResult.textContent = describeRestoreProgress(p);
      });
      browseResult.textContent = describeRestoreResult(body);
      browseResult.style.color = "var(--ok)";
    } catch (err) {
      browseResult.textContent = "Restore failed: " + err.message;
      browseResult.style.color = "var(--danger)";
    } finally {
      btn.disabled = false;
    }
  });

  row.querySelector(".file-purge")?.addEventListener("click", async (ev) => {
    const ok = window.confirm(
      "Delete permanently?\n\n" + item.path + "\n\n" +
      "You deleted this file, but your buddy is keeping copies of it for 30 days in case you need it back. " +
      "This removes those copies now, so it can't be restored afterwards. Nothing on this device is changed."
    );
    if (!ok) return;
    const btn = ev.target;
    btn.disabled = true;
    browseResult.textContent = "Deleting " + item.path + " permanently…";
    browseResult.style.color = "";
    try {
      const res = await fetch("/api/buddies/" + encodeURIComponent(browseState.nodeId) + "/purge", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: item.path }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || ("HTTP " + res.status));
      browseState.files = browseState.files.filter((f) => f.path !== item.path);
      browseState.tree = buildFileTree(browseState.files);
      renderBrowseView();
      browseResult.textContent = "Deleted " + item.path + " permanently.";
      browseResult.style.color = "var(--ok)";
    } catch (err) {
      btn.disabled = false;
      browseResult.textContent = "Couldn't delete permanently: " + err.message;
      browseResult.style.color = "var(--danger)";
    }
  });

  let historyLoaded = false;
  row.querySelector(".file-history-toggle").addEventListener("click", async () => {
    const wasOpen = history.style.display !== "none";
    history.style.display = wasOpen ? "none" : "block";
    if (wasOpen || historyLoaded) return;
    historyLoaded = true;
    history.textContent = "Checking for older versions…";
    try {
      const res = await fetch(
        "/api/buddies/" + encodeURIComponent(browseState.nodeId) + "/versions?path=" +
        encodeURIComponent(item.path)
      );
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || ("HTTP " + res.status));
      renderVersionHistory(history, item.path, body.versions || []);
    } catch (err) {
      historyLoaded = false; // allow a retry on the next click
      history.textContent = "Couldn't load version history: " + err.message;
    }
  });

  frag.appendChild(row);
  frag.appendChild(history);
  return frag;
}

// Every overwrite or delete keeps the previous content as a numbered
// backup slot (see receive.rs::rotate_versions) — this lists whatever
// slots a buddy still has for one path and lets the person pull an older
// one back, separately from a normal restore (which only ever gives you
// the live copy).
function renderVersionHistory(container, path, versions) {
  if (versions.length === 0) {
    container.textContent = "No earlier versions kept for this file.";
    return;
  }
  container.innerHTML = "";
  for (const v of versions) {
    let when = v.modified_unix ? fmtAgo(v.modified_unix) : "at an unknown time";
    // Buddies on 0.8.2+ remove copies after 30 days and say when.
    if (v.expires_unix) {
      const days = Math.max(0, Math.ceil((v.expires_unix - Date.now() / 1000) / 86400));
      when += days > 0 ? ", removed in " + days + " day" + (days === 1 ? "" : "s") : ", removed soon";
    }
    const row = document.createElement("div");
    row.className = "version-row";
    row.innerHTML = `
      <span>Version ${v.version} — ${fmtBytes(v.size)}, kept ${when}</span>
      <button class="secondary version-restore">Restore this version</button>
    `;
    row.querySelector(".version-restore").addEventListener("click", async (ev) => {
      const btn = ev.target;
      btn.disabled = true;
      browseResult.textContent = "Restoring version " + v.version + " of " + path + "…";
      browseResult.style.color = "";
      try {
        const res = await fetch("/api/restore-version/" + encodeURIComponent(browseState.nodeId), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ path, version: v.version }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(body.error || ("HTTP " + res.status));
        browseResult.textContent = describeRestoreResult(body) + " (as a separate .v" + v.version + ".bak file)";
        browseResult.style.color = "var(--ok)";
      } catch (err) {
        browseResult.textContent = "Restore failed: " + err.message;
        browseResult.style.color = "var(--danger)";
      } finally {
        btn.disabled = false;
      }
    });
    container.appendChild(row);
  }
}

function makeFolderRow(name, node, path) {
  const paths = collectPaths(node);
  const row = document.createElement("div");
  row.className = "file-row";
  row.innerHTML = `
    <input type="checkbox" class="file-pick">
    <span class="file-icon">📁</span>
    <a href="javascript:void(0)" class="path folder-link">${name}/</a>
    <span class="size">${paths.length} file(s)</span>
    <button class="secondary folder-restore">Restore</button>
  `;
  const checkbox = row.querySelector(".file-pick");
  checkbox.checked = paths.length > 0 && paths.every((p) => browseState.selected.has(p));
  checkbox.addEventListener("change", () => {
    if (checkbox.checked) paths.forEach((p) => browseState.selected.add(p));
    else paths.forEach((p) => browseState.selected.delete(p));
    renderBrowseView();
  });
  row.querySelector(".folder-link").addEventListener("click", (ev) => {
    ev.preventDefault();
    browseState.currentPath = path;
    renderBrowseView();
  });
  row.querySelector(".folder-restore").addEventListener("click", async (ev) => {
    const btn = ev.target;
    btn.disabled = true;
    browseResult.textContent = "Restoring " + paths.length + " file(s) from " + name + "/…";
    browseResult.style.color = "";
    try {
      const body = await doRestore(browseState.nodeId, paths, (p) => {
        browseResult.textContent = describeRestoreProgress(p);
      });
      browseResult.textContent = describeRestoreResult(body);
      browseResult.style.color = "var(--ok)";
    } catch (err) {
      browseResult.textContent = "Restore failed: " + err.message;
      browseResult.style.color = "var(--danger)";
    } finally {
      btn.disabled = false;
    }
  });
  return row;
}

// Folder view: breadcrumb + the current directory's subfolders (sorted)
// then its own files (sorted) — one level at a time, not the whole tree
// flattened out.
function renderBrowseFolder() {
  browseBreadcrumb.style.display = "flex";
  if (nodeAtPath(browseState.currentPath) === null) browseState.currentPath = "";
  renderBreadcrumb();

  const node = nodeAtPath(browseState.currentPath) || browseState.tree || { dirs: new Map(), items: [] };
  const dirNames = Array.from(node.dirs.keys()).sort();
  const items = node.items.slice().sort((a, b) => a.name.localeCompare(b.name));

  browseList.innerHTML = "";
  for (const name of dirNames) {
    const path = browseState.currentPath ? browseState.currentPath + "/" + name : name;
    browseList.appendChild(makeFolderRow(name, node.dirs.get(name), path));
  }
  for (const item of items) {
    browseList.appendChild(makeFileRow(item));
  }

  const visiblePaths = collectPaths(node);
  browseCount.textContent = dirNames.length + " folder(s), " + items.length + " file(s) here";
  browseSelectAll.checked = visiblePaths.length > 0 && visiblePaths.every((p) => browseState.selected.has(p));
  updateSelectedControls();
}

// Search view: flat, full-path matches across everything the buddy has,
// regardless of which folder is open — someone searching usually doesn't
// remember which folder a file lives in.
function renderBrowseSearch(query) {
  browseBreadcrumb.style.display = "none";
  const filtered = browseState.files.filter((f) => f.path.toLowerCase().includes(query));

  browseCount.textContent = filtered.length + " of " + browseState.files.length + " file(s)";
  browseList.innerHTML = "";
  for (const f of filtered) {
    browseList.appendChild(makeFileRow({ name: f.path, path: f.path, size: f.size, deleted: !!f.deleted }));
  }

  browseSelectAll.checked = filtered.length > 0 && filtered.every((f) => browseState.selected.has(f.path));
  updateSelectedControls();
}

function renderBrowseView() {
  const query = browseSearch.value.trim().toLowerCase();
  if (query) renderBrowseSearch(query);
  else renderBrowseFolder();
}

function updateSelectedControls() {
  browseRestoreSelected.disabled = browseState.selected.size === 0;
  browseRestoreSelected.textContent =
    browseState.selected.size > 0 ? "Restore selected (" + browseState.selected.size + ")" : "Restore selected";
}

async function openBrowseModal(nodeId, label) {
  browseState.nodeId = nodeId;
  browseState.label = label;
  browseState.files = [];
  browseState.tree = null;
  browseState.currentPath = "";
  browseState.selected.clear();
  browseSearch.value = "";
  browseResult.textContent = "";
  browseTitle.textContent = "Files from " + label;
  browseCount.textContent = "";
  browseList.innerHTML = "";
  browseBreadcrumb.innerHTML = "";
  browseModal.classList.add("open");

  try {
    const res = await fetch("/api/buddies/" + encodeURIComponent(nodeId) + "/files");
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || ("HTTP " + res.status));
    browseState.files = (body.files || []).slice().sort((a, b) => a.path.localeCompare(b.path));
    browseState.tree = buildFileTree(browseState.files);
    renderBrowseView();
  } catch (err) {
    browseList.innerHTML = "";
    browseCount.textContent = "";
    browseResult.textContent = "Couldn't list files: " + err.message;
    browseResult.style.color = "var(--danger)";
  }
}

browseSearch.addEventListener("input", renderBrowseView);
document.getElementById("browse-close").addEventListener("click", closeBrowseModal);
browseModal.addEventListener("click", (ev) => {
  if (ev.target === browseModal) closeBrowseModal();
});

browseSelectAll.addEventListener("change", () => {
  const query = browseSearch.value.trim().toLowerCase();
  const paths = query
    ? browseState.files.filter((f) => f.path.toLowerCase().includes(query) && !f.deleted).map((f) => f.path)
    : collectPaths(nodeAtPath(browseState.currentPath) || browseState.tree || { dirs: new Map(), items: [] });
  if (browseSelectAll.checked) {
    paths.forEach((p) => browseState.selected.add(p));
  } else {
    paths.forEach((p) => browseState.selected.delete(p));
  }
  renderBrowseView();
});

browseRestoreSelected.addEventListener("click", async () => {
  const paths = Array.from(browseState.selected);
  if (paths.length === 0) return;
  browseRestoreSelected.disabled = true;
  browseResult.textContent = "Restoring " + paths.length + " file(s)…";
  browseResult.style.color = "";
  try {
    const body = await doRestore(browseState.nodeId, paths, (p) => {
      browseResult.textContent = describeRestoreProgress(p);
    });
    browseResult.textContent = describeRestoreResult(body);
    browseResult.style.color = "var(--ok)";
  } catch (err) {
    browseResult.textContent = "Restore failed: " + err.message;
    browseResult.style.color = "var(--danger)";
  } finally {
    browseRestoreSelected.disabled = browseState.selected.size === 0;
  }
});

browseRestoreAll.addEventListener("click", async () => {
  browseRestoreAll.disabled = true;
  browseResult.textContent = "Restoring everything…";
  browseResult.style.color = "";
  try {
    const body = await doRestore(browseState.nodeId, [], (p) => {
      browseResult.textContent = describeRestoreProgress(p);
    });
    browseResult.textContent = describeRestoreResult(body);
    browseResult.style.color = "var(--ok)";
  } catch (err) {
    browseResult.textContent = "Restore failed: " + err.message;
    browseResult.style.color = "var(--danger)";
  } finally {
    browseRestoreAll.disabled = false;
  }
});

// Must match protocol.rs's RejectReason::message() for PledgeExceeded and
// DiskFull.
const DONT_FIT_REASONS = [
  "your buddy's pledge to you is full",
  "your buddy doesn't have enough real disk space left",
];

function renderBuddy(b) {
  const pct = b.pledged_bytes > 0 ? Math.min(100, (b.received_bytes_counted / b.pledged_bytes) * 100) : 0;
  const cycle = b.last_cycle;
  // Files the buddy refused only because they don't fit (pledge or disk
  // full) aren't a broken backup: everything else synced, and nothing will
  // change until the pledge grows or the files go. Shown as a calm amber
  // "don't fit" instead of a red "backup failed".
  const onlyDontFit =
    cycle && !cycle.ok && cycle.kind === "backup" && cycle.files_failed > 0 &&
    cycle.failed_files && cycle.failed_files.length > 0 &&
    cycle.failed_files.every((f) => DONT_FIT_REASONS.includes(f.reason));
  let cyclePill = '<span class="pill pill-pending">no cycle yet</span>';
  let cycleDetail = "";
  if (cycle) {
    cyclePill = cycle.ok
      ? '<span class="pill pill-ok">' + cycle.kind + ' ok</span>'
      : onlyDontFit
        ? '<span class="pill pill-warn">' + cycle.files_failed + " file(s) don't fit</span>"
        : '<span class="pill pill-err">' + cycle.kind + ' failed</span>';
    cycleDetail = (onlyDontFit ? "everything else is backed up" : cycle.detail) + " · " + fmtAgo(cycle.at);
    if (cycle.kind === "backup" && cycle.ok) {
      cycleDetail = "sent " + (cycle.files_sent ?? 0) + ", deleted " + (cycle.files_deleted ?? 0) + " · " + fmtAgo(cycle.at);
      const rate = fmtRate(cycle.bytes_sent, cycle.duration_ms);
      if (rate) {
        cycleDetail +=
          " · " + fmtBytes(cycle.bytes_sent) + " in " + (cycle.duration_ms / 1000).toFixed(1) + "s (" + rate + ")";
      }
      if (cycle.connection) cycleDetail += " · " + fmtConnection(cycle.connection);
    }
    if (cycle.consecutive_failures > 1 && !onlyDontFit) {
      cycleDetail += " · " + cycle.consecutive_failures + " cycles in a row now";
    }
  }

  // A cycle running right now replaces "no cycle yet" with "backing up…"
  // and shows live progress above the last cycle's line, so a long first
  // backup visibly moves instead of looking stuck.
  let progressBlock = "";
  if (b.in_progress) {
    const prog = describeCycleProgress(b.in_progress);
    const pctW = Math.max(0, Math.min(100, prog.frac * 100)).toFixed(1);
    progressBlock =
      '<div style="margin-top: 0.4rem;"><div class="muted">' + escapeHtml(prog.line) + "</div>" +
      '<div class="bar-track"><div class="bar-fill" style="width:' + pctW + '%"></div></div></div>';
    const running = b.in_progress.phase === "checking" ? "checking files" : "backing up";
    cyclePill = '<span class="pill pill-pending">' + running + "…</span>";
    if (cycle) cycleDetail = "last cycle: " + cycleDetail;
  }

  // A buddy can look "ok" on the very latest cycle (kind pill) while still
  // having gone a long time without a *successful* one, or have files that
  // keep failing cycle after cycle — both worth a loud, separate warning
  // rather than burying them in the one-line cycle detail above.
  let stalePill = "";
  if (b.stale) {
    const lastOkText = cycle && cycle.last_synced_at ? fmtAgo(cycle.last_synced_at) : "never";
    stalePill = ' <span class="pill pill-err">stale — last synced ' + lastOkText + '</span>';
  }
  let failedLine = "";
  if (onlyDontFit) {
    const sample = cycle.failed_files.map((f) => escapeHtml(f.path)).join(", ");
    const more = cycle.files_failed > cycle.failed_files.length ? ", …" : "";
    failedLine =
      '<div class="muted" style="margin-top: 0.4rem;">' +
      cycle.files_failed + " file(s) don't fit in what this buddy has room for. " +
      "They'll go as soon as there's space: ask your buddy for a bigger pledge, or remove files from your backup folder." +
      '<details style="margin-top: 0.2rem;"><summary>Which files</summary>' + sample + more + "</details></div>";
  } else if (cycle && cycle.files_failed > 0) {
    const sample =
      cycle.failed_files && cycle.failed_files.length
        ? ": " + cycle.failed_files.map((f) => escapeHtml(f.path) + (f.reason ? " (" + f.reason + ")" : "")).join(", ")
        : "";
    failedLine =
      '<div class="muted" style="color: var(--danger); margin-top: 0.4rem;">⚠ ' +
      cycle.files_failed + " file(s) won't send/receive" + sample + "</div>";
  }

  // Reconciliation runs on its own, much slower cadence (every ~10
  // minutes, not every cycle — see backup::reconcile_with_buddy), so this
  // is deliberately separate from the ordinary cycle detail above rather
  // than folded into it.
  let reconcileLine = "";
  const rec = b.last_reconcile;
  if (rec) {
    if (rec.error) {
      reconcileLine =
        '<div class="muted" style="color: var(--danger); margin-top: 0.4rem;">⚠ reconciliation check failed ' +
        fmtAgo(rec.at) + ": " + rec.error + "</div>";
    } else if (rec.missing_on_buddy.length || rec.unexpected_on_buddy.length) {
      const parts = [];
      if (rec.missing_on_buddy.length) {
        parts.push(
          rec.missing_on_buddy.length + " missing on buddy (will re-send): " + rec.missing_on_buddy.join(", ")
        );
      }
      if (rec.unexpected_on_buddy.length) {
        parts.push(
          rec.unexpected_on_buddy.length + " unexpected on buddy: " + rec.unexpected_on_buddy.join(", ")
        );
      }
      reconcileLine =
        '<div class="muted" style="color: var(--danger); margin-top: 0.4rem;">⚠ reconciliation (' +
        fmtAgo(rec.at) + ") found drift — " + parts.join("; ") + "</div>";
    } else if (rec.checked > 0) {
      reconcileLine =
        '<div class="muted" style="margin-top: 0.4rem;">✓ reconciled ' + fmtAgo(rec.at) +
        " — " + rec.checked + " file(s) match the buddy's actual records</div>";
    }
    // checked === 0 with no error means an empty manifest — nothing to
    // reconcile yet, so no line at all rather than a confusing "0 files
    // match" message.
  }

  const div = document.createElement("div");
  div.className = "card";
  div.innerHTML = `
    <div class="row">
      <h2>${b.label ? b.label : b.node_id.slice(0, 12) + "…"}</h2>
      <div>${cyclePill}${stalePill}</div>
    </div>
    ${progressBlock}
    <div class="muted">${cycleDetail}</div>
    ${failedLine}
    ${reconcileLine}
    <div class="row" style="margin-top: 0.9rem;">
      <div>
        <div class="muted">You've sent them</div>
        <div>${b.sent_files} file(s), ${fmtBytes(b.sent_bytes)}</div>
      </div>
      <div>
        <div class="muted">They've sent you</div>
        <div>${b.received_files} file(s), ${fmtBytes(b.received_total_bytes)}</div>
      </div>
    </div>
    <div style="margin-top: 0.75rem;">
      <div class="muted">Their pledge to you: ${fmtBytes(b.received_bytes_counted)} / ${fmtBytes(b.pledged_bytes)}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
    </div>
    <div class="muted" style="margin-top: 0.75rem;">
      Their actual disk:
      <span class="buddy-disk" data-node-id="${b.node_id}">checking…</span>
      <button class="secondary buddy-disk-recheck" data-node-id="${b.node_id}">Recheck</button>
    </div>
    <div style="margin-top: 1rem;">
      <button class="restore-btn" data-node-id="${b.node_id}">Restore from this buddy</button>
      <button class="secondary browse-btn" data-node-id="${b.node_id}">Browse files…</button>
      <div class="restore-result" data-node-id="${b.node_id}"></div>
    </div>
  `;
  const btn = div.querySelector(".restore-btn");
  btn.addEventListener("click", () => restoreNow(b.node_id));
  // Re-apply any restore result/progress from before this rebuild.
  applyRestoreStatus(b.node_id, div);
  const browseBtn = div.querySelector(".browse-btn");
  const label = b.label ? b.label : b.node_id.slice(0, 12) + "…";
  browseBtn.addEventListener("click", () => openBrowseModal(b.node_id, label));

  div.querySelector(".buddy-disk-recheck").addEventListener("click", () => {
    buddyDiskLastFetched.set(b.node_id, Date.now());
    fetchBuddyDisk(b.node_id);
  });
  // Scoped to `div` itself, not `document` — at this point renderBuddy's
  // caller (refresh()) hasn't appended it to the page yet, so a
  // document-wide query would find nothing and silently no-op, leaving
  // the span stuck on its literal "checking…" template text even when
  // buddyDiskCache already has a real value from an earlier fetch.
  applyBuddyDisk(b.node_id, div);
  const lastFetched = buddyDiskLastFetched.get(b.node_id);
  if (!lastFetched || Date.now() - lastFetched > BUDDY_DISK_RECHECK_MS) {
    buddyDiskLastFetched.set(b.node_id, Date.now());
    fetchBuddyDisk(b.node_id);
  }

  return div;
}

function renderDisk(data) {
  const card = document.getElementById("disk-card");
  if (!data.disk) {
    card.style.display = "none";
    return;
  }
  card.style.display = "block";

  document.getElementById("buddy-files-dir").textContent = data.buddy_files_dir;
  document.getElementById("disk-used").textContent = fmtBytes(data.disk.used_bytes);
  document.getElementById("disk-free").textContent = fmtBytes(data.disk.available_bytes);
  document.getElementById("disk-total").textContent = fmtBytes(data.disk.total_bytes);
  document.getElementById("disk-pledged").textContent = fmtBytes(data.pledged_out_total_bytes);

  const usedPct = data.disk.total_bytes > 0 ? (data.disk.used_bytes / data.disk.total_bytes) * 100 : 0;
  const bar = document.getElementById("disk-bar");
  bar.style.width = Math.min(100, usedPct) + "%";

  // The number that actually matters: can the disk cover what's been
  // pledged to buddies on top of what's already used? Pledges aren't
  // necessarily all consumed yet, so this is a "could run out" warning,
  // not a "is out" one.
  const warningEl = document.getElementById("disk-warning");
  const committedTotal = data.disk.used_bytes + data.pledged_out_total_bytes;
  if (data.pledged_out_total_bytes > data.disk.available_bytes) {
    bar.classList.add("bar-fill-warn");
    warningEl.style.display = "block";
    warningEl.textContent =
      "You've pledged " + fmtBytes(data.pledged_out_total_bytes) + " to buddies, but only " +
      fmtBytes(data.disk.available_bytes) + " is actually free on this disk (" +
      fmtBytes(committedTotal) + " committed against " + fmtBytes(data.disk.total_bytes) + " total). " +
      "If buddies fill their pledges, this disk will run out.";
  } else {
    bar.classList.remove("bar-fill-warn");
    warningEl.style.display = "none";
  }
}

// Relay vs. direct is shown as a split bar (relay first) so it's obvious
// at a glance how much of this device's lifetime traffic actually costs
// relay bandwidth vs. went peer-to-peer for free.
function renderBandwidth(data) {
  const bw = data.bandwidth || { relay_bytes: 0, direct_bytes: 0 };
  const total = bw.relay_bytes + bw.direct_bytes;
  document.getElementById("bw-relay").textContent = fmtBytes(bw.relay_bytes);
  document.getElementById("bw-direct").textContent = fmtBytes(bw.direct_bytes);
  document.getElementById("bw-total").textContent = fmtBytes(total);

  const relayPct = total > 0 ? (bw.relay_bytes / total) * 100 : 0;
  document.getElementById("bw-bar").style.width = relayPct + "%";

  const note = document.getElementById("bw-note");
  note.textContent =
    total === 0
      ? "Nothing transferred yet."
      : Math.round(relayPct) + "% of all traffic so far has gone through the relay rather than direct.";
}

async function refresh() {
  const res = await fetch("/api/status");
  const data = await res.json();
  // Prefer the human-readable label set in the web dashboard's Devices
  // card (see dashboard.rs's AppState::self_label) — falls back to the
  // bare node id until that's known, same fallback the buddy cards below
  // already use for their own label/node_id pairs. When a label is known,
  // the full node id is still shown alongside it (muted) since it's
  // sometimes needed for support/debugging.
  document.getElementById("device-label").textContent = data.label || data.node_id;
  document.getElementById("node-id").textContent = data.label ? "(" + data.node_id + ")" : "";
  document.getElementById("backup-dir").textContent = data.backup_dir || "(nothing — receive-only)";

  document.getElementById("device-version").textContent = data.version;
  // Update verdict — only shown once a check has actually succeeded. A
  // missing latest_version means "couldn't check" (offline, or checking is
  // off), which must not read as "up to date".
  const updateBox = document.getElementById("device-update");
  const updatePill = document.getElementById("device-update-pill");
  const updateCmd = document.getElementById("device-update-cmd");
  if (data.latest_version) {
    updateBox.style.display = "";
    if (data.update_available) {
      updatePill.className = "pill pill-warn";
      updatePill.textContent = "Update available: " + data.latest_version;
      updateCmd.textContent = data.update_command;
      updateCmd.style.display = "";
    } else {
      updatePill.className = "pill pill-ok";
      updatePill.textContent = "Up to date";
      updateCmd.style.display = "none";
    }
  } else {
    updateBox.style.display = "none";
  }
  document.getElementById("device-uptime").textContent = fmtUptime(data.uptime_secs);
  document.getElementById("device-mdns-peers").textContent =
    data.mdns_peers_visible + (data.mdns_peers_visible === 1 ? " peer" : " peers");
  document.getElementById("device-cycle-interval").textContent = data.cycle_interval_secs + "s";
  const localFilesStat = document.getElementById("local-files-stat");
  const localSizeStat = document.getElementById("local-size-stat");
  if (data.local_backup) {
    localFilesStat.style.display = "block";
    localSizeStat.style.display = "block";
    document.getElementById("local-files-count").textContent = data.local_backup.file_count;
    document.getElementById("local-files-size").textContent = fmtBytes(data.local_backup.total_bytes);
  } else {
    localFilesStat.style.display = "none";
    localSizeStat.style.display = "none";
  }

  renderDisk(data);
  renderBandwidth(data);

  const container = document.getElementById("buddies");
  const empty = document.getElementById("empty");
  if (data.buddies.length === 0) {
    empty.style.display = "block";
    container.innerHTML = "";
    return;
  }
  empty.style.display = "none";
  container.innerHTML = "";
  for (const b of data.buddies) container.appendChild(renderBuddy(b));
}

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
"#;
