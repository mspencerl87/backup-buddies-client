// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

//! What restores report (chunked_restore.rs does the work), and a buddy's
//! disk numbers for the dashboard.

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl};
use serde::Serialize;

use crate::netinfo::{self, ConnectionQuality};
use crate::protocol::{self, DiskStatsResponse, SyncRequest};

/// Live progress for one in-flight multi-file restore, polled by the
/// dashboard (GET /api/buddies/:id/restore-progress) while the restore's
/// own POST is still in flight — the two are separate requests so a slow
/// restore doesn't leave the browser with nothing to show but a frozen
/// "Restoring…" for however long it takes. `total_files`/`total_bytes`
/// are set once up front by whoever creates the handle (they come from the
/// file list); the restore only ever advances
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
/// the same way.
#[derive(Debug, Clone, Copy, Default)]
pub struct RestoreStats {
    pub files_restored: usize,
    pub bytes_restored: u64,
    pub duration_ms: u64,
    pub connection: Option<ConnectionQuality>,
    // Bytes received, split by path (see netinfo::PathMeter).
    pub traffic: Option<netinfo::ByteSplit>,
}

/// One file in our backup on a buddy, by its path in the backup folder.
#[derive(Debug, Clone, Serialize)]
pub struct BuddyFile {
    pub path: String,
    pub size: u64,
    /// Only in older snapshots: deleted (or renamed away) since, and still
    /// restorable from History until those snapshots age out.
    pub deleted: bool,
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
    let addr = EndpointAddr::new(buddy_id).with_relay_url(relay_url.clone());
    let conn = endpoint.connect(addr, protocol::ALPN).await.map_err(protocol::explain_connect_error)?;
    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;
    protocol::write_frame(&mut send, &SyncRequest::DiskStats).await?;
    send.finish().context("failed to finish send stream")?;
    let stats: DiskStatsResponse =
        protocol::read_frame(&mut recv).await.context("failed to read disk stats")?;
    Ok((stats, netinfo::connection_quality(&conn)))
}
