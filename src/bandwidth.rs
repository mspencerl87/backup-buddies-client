// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::netinfo::{ConnectionQuality, PathKind};

// Lifetime, cumulative byte counts, split by which network path actually
// carried them — not per-buddy, since what matters here is "how much of
// this device's traffic went over relay.filegarden.net" (the thing that
// would actually cost something to meter/bill), not who it was with.
// Covers every data-moving exchange this device takes part in, either
// direction: our own backup pushes and restore pulls, and a buddy pushing
// to us or pulling from us. Control traffic (Ping, List, DiskStats,
// Delete) is negligible and isn't counted.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct BandwidthTotals {
    pub relay_bytes: u64,
    pub direct_bytes: u64,
    // High-water mark: how much of relay_bytes has already been reported to
    // the API (see main.rs's buddies-poll loop and
    // apps/api/src/lib/relay-billing.js). Only relay traffic is ever
    // billable — direct peer-to-peer transfers don't touch the relay and
    // aren't reported at all. Persisted alongside the totals so a restart
    // doesn't re-report (or lose track of) anything: the delta sent each
    // poll is always `relay_bytes - reported_relay_bytes` at that moment.
    #[serde(default)]
    pub reported_relay_bytes: u64,
}

pub type BandwidthBook = Arc<Mutex<BandwidthTotals>>;

pub async fn load(data_dir: &Path) -> BandwidthTotals {
    match tokio::fs::read(data_dir.join("bandwidth.json")).await {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => BandwidthTotals::default(),
    }
}

pub async fn save(data_dir: &Path, book: &BandwidthBook) -> Result<()> {
    let snapshot = *book.lock().unwrap();
    let json = serde_json::to_vec(&snapshot)?;
    tokio::fs::write(data_dir.join("bandwidth.json"), json).await?;
    Ok(())
}

/// Adds `bytes` to the running total for whichever path carried them, then
/// persists the new total. `Unknown` (a connection whose path hadn't
/// settled when read) is dropped rather than guessed into either bucket —
/// undercounting slightly is better than misattributing relay-billable
/// bytes as free direct ones, or vice versa.
pub async fn record(data_dir: &Path, book: &BandwidthBook, quality: &ConnectionQuality, bytes: u64) {
    if bytes == 0 {
        return;
    }
    {
        let mut totals = book.lock().unwrap();
        match quality.path {
            PathKind::Relay => totals.relay_bytes += bytes,
            PathKind::Direct => totals.direct_bytes += bytes,
            PathKind::Unknown => return,
        }
    }
    if let Err(err) = save(data_dir, book).await {
        tracing::warn!(?err, "failed to persist bandwidth totals");
    }
}

/// Adds a connection's relay/direct split (see netinfo::PathMeter) and
/// persists the new totals.
pub async fn record_split(data_dir: &Path, book: &BandwidthBook, split: crate::netinfo::ByteSplit) {
    if split.relay == 0 && split.direct == 0 {
        return;
    }
    {
        let mut totals = book.lock().unwrap();
        totals.relay_bytes += split.relay;
        totals.direct_bytes += split.direct;
    }
    if let Err(err) = save(data_dir, book).await {
        tracing::warn!(?err, "failed to persist bandwidth totals");
    }
}

const BYTES_PER_MB: u64 = 1024 * 1024;

/// Whole megabytes of relay traffic accumulated since the last successful
/// report to the API. Floors rather than rounds, so a fraction of a
/// megabyte just stays pending for the next poll instead of ever being
/// reported (and then re-marked-reported) twice.
pub fn pending_relay_mb(book: &BandwidthBook) -> u64 {
    let totals = book.lock().unwrap();
    totals
        .relay_bytes
        .saturating_sub(totals.reported_relay_bytes)
        / BYTES_PER_MB
}

/// Advances the reported high-water mark by `mb` (whole megabytes) and
/// persists it. Call this only after the API has confirmed it received the
/// report — on failure, leave it unmarked so the same bytes are simply
/// included in the next poll's delta rather than lost.
pub async fn mark_relay_reported(data_dir: &Path, book: &BandwidthBook, mb: u64) {
    if mb == 0 {
        return;
    }
    {
        let mut totals = book.lock().unwrap();
        totals.reported_relay_bytes = totals.reported_relay_bytes.saturating_add(mb * BYTES_PER_MB);
    }
    if let Err(err) = save(data_dir, book).await {
        tracing::warn!(?err, "failed to persist bandwidth totals after relay report");
    }
}
