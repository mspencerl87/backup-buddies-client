// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

use iroh::endpoint::Connection;
use serde::Serialize;

/// Which kind of network path a connection ended up using. iroh tries a
/// direct, hole-punched peer-to-peer path first and falls back to relaying
/// through relay.filegarden.net when NAT traversal doesn't work out —
/// this is how the dashboard shows which one actually happened for a
/// given backup/restore, without anyone needing to know what iroh or QUIC
/// paths are.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    Direct,
    Relay,
    /// The connection hadn't settled on a path yet when this was read —
    /// shown as "checking" rather than guessing one way or the other.
    Unknown,
}

/// A snapshot of the network path actually carrying a connection's
/// traffic right now, plus round-trip latency on that path. None of this
/// is wire protocol — it's purely local telemetry about *our* link to the
/// buddy, read straight off iroh's connection object, so it costs nothing
/// extra on the network.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ConnectionQuality {
    pub path: PathKind,
    pub rtt_ms: Option<u64>,
}

/// Reads the currently-selected path off a live connection.
pub fn connection_quality(conn: &Connection) -> ConnectionQuality {
    let paths = conn.paths();
    match paths.iter().find(|p| p.is_selected()) {
        Some(p) => ConnectionQuality {
            path: if p.is_relay() { PathKind::Relay } else { PathKind::Direct },
            rtt_ms: Some(p.rtt().as_millis() as u64),
        },
        None => ConnectionQuality { path: PathKind::Unknown, rtt_ms: None },
    }
}

/// Bytes a connection carried over relay paths vs. direct ones.
#[derive(Debug, Clone, Copy, Default)]
pub struct ByteSplit {
    pub relay: u64,
    pub direct: u64,
}

/// Which way to count: what we sent (a backup) or received (a restore).
#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Sent,
    Received,
}

/// Splits a connection's bytes between relay and direct paths over its
/// whole life. Reading only the path selected at the end used to book
/// everything there: seen live, a LAN path closed at the end of a 5 GB
/// cycle and all of it was counted (and reported for billing) as relay.
/// Closed paths drop out of `paths()`, so their final numbers are collected
/// from path events as they close; open ones are read at the end. Relay is
/// what was measured on relay paths and everything else is direct, so a
/// missed event can only under-count relay, never bill direct bytes.
pub struct PathMeter {
    closed_relay: std::sync::Arc<std::sync::atomic::AtomicU64>,
    direction: Direction,
    task: tokio::task::JoinHandle<()>,
}

fn path_bytes(stats: &iroh::endpoint::PathStats, direction: Direction) -> u64 {
    match direction {
        Direction::Sent => stats.udp_tx.bytes,
        Direction::Received => stats.udp_rx.bytes,
    }
}

impl PathMeter {
    pub fn start(conn: &Connection, direction: Direction) -> Self {
        use n0_future::StreamExt;
        let closed_relay = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut events = conn.path_events();
        let counter = closed_relay.clone();
        let task = tokio::spawn(async move {
            while let Some(event) = events.next().await {
                if let iroh::endpoint::PathEvent::Closed { remote_addr, last_stats, .. } = event
                    && remote_addr.is_relay()
                {
                    counter.fetch_add(path_bytes(&last_stats, direction), std::sync::atomic::Ordering::Relaxed);
                }
            }
        });
        Self { closed_relay, direction, task }
    }

    pub fn finish(self, conn: &Connection) -> ByteSplit {
        let open_relay: u64 = conn
            .paths()
            .iter()
            .filter(|p| p.is_relay())
            .map(|p| path_bytes(&p.stats(), self.direction))
            .sum();
        self.task.abort();
        let stats = conn.stats();
        let total = match self.direction {
            Direction::Sent => stats.udp_tx.bytes,
            Direction::Received => stats.udp_rx.bytes,
        };
        let relay = (open_relay + self.closed_relay.load(std::sync::atomic::Ordering::Relaxed)).min(total);
        ByteSplit { relay, direct: total - relay }
    }
}
