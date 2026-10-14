// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

// One protocol name for every client version. Newer features are found by
// asking (SyncRequest::Hello), not by a new ALPN: an ALPN a peer doesn't
// support makes iroh connections hang until timeout rather than fail fast,
// which would break every pairing where one buddy updated first.
pub const ALPN: &[u8] = b"backup-buddies/sync/1";

/// This client's protocol version, reported in HelloResponse. 5 (client
/// 0.16.0) added the Repo* requests, a buddy storing a chunked backup
/// repository (see repo.rs); since client 0.21.0 that's the only kind of
/// backup, and the whole-file requests of versions 1–4 are gone.
pub const PROTOCOL_VERSION: u32 = 5;

pub fn explain_connect_error(err: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("failed to connect to buddy: {err}")
}

// Every exchange on a stream starts with one framed SyncRequest, answered
// with a framed reply (see each request), followed by raw bytes for
// RepoRead. Framing is a 4-byte little-endian length prefix followed by
// that many bytes of JSON — simple, and keeps control messages clearly
// separated from the raw file bytes that follow some of them on the same
// stream.
const MAX_FRAME_BYTES: usize = 1024 * 1024; // control messages are tiny; generous headroom

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum SyncRequest {
    /// No backup work to do this cycle — just prove the connection still
    /// works. Same purpose the old test-payload protocol served.
    Ping,
    /// "Which protocol version do you speak?" Answered with HelloResponse.
    /// A client older than 0.5.0 can't parse this and drops the stream,
    /// which reads as version 1.
    Hello,
    /// "What does your disk actually look like?" — real filesystem space
    /// plus how much of it you've committed across every buddy, not just
    /// what you've pledged me. Answered with DiskStatsResponse. Lets each
    /// side's dashboard show the other's real numbers instead of just
    /// trusting the pledge they agreed to, so an over-pledged or
    /// nearly-full buddy is visible before it becomes a failed backup.
    DiskStats,
    /// Protocol v5: "Which repository files of this kind do you hold for
    /// me?" Answered with RepoListChunk frames (REPO_LIST_CHUNK_ENTRIES
    /// each, last one `done: true`). The repository is a restic-format one
    /// the sender builds with rustic_core: the buddy only ever stores,
    /// lists and hands back opaque encrypted files, by kind and id.
    RepoList { kind: RepoFileKind },
    /// Protocol v5: "Send me `length` bytes of this repository file from
    /// `offset`" (the rest of the file when `length` is None). Answered
    /// with a RepoReadReply, then on success exactly that many raw bytes.
    RepoRead { kind: RepoFileKind, id: String, offset: u64, length: Option<u64> },
    /// Protocol v5: "Store this repository file." Followed by exactly `len`
    /// raw bytes; answered with a SyncAck, or refused before the body
    /// (STOP_SENDING with a PutRejectReason code).
    RepoWrite { kind: RepoFileKind, id: String, len: u64 },
    /// Protocol v5: "Remove this repository file." Answered with a SyncAck.
    /// Idempotent: removing something already gone is not an error.
    RepoRemove { kind: RepoFileKind, id: String },
}

/// The kinds of file in a restic-format repository (rustic_core's
/// FileType). Every kind but Config is named by the SHA-256 of its
/// contents, which the buddy checks on every write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoFileKind {
    Config,
    Index,
    Key,
    Snapshot,
    Pack,
}

pub const REPO_LIST_CHUNK_ENTRIES: usize = 5000;

#[derive(Debug, Serialize, Deserialize)]
pub struct RepoFileEntry {
    pub id: String,
    pub size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RepoListChunk {
    pub files: Vec<RepoFileEntry>,
    pub done: bool,
}

/// Answer to RepoRead, before any file bytes: `len` is how many follow
/// (None when the file isn't there or the range is bad, with `error`).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RepoReadReply {
    #[serde(default)]
    pub len: Option<u64>,
    #[serde(default)]
    pub error: Option<String>,
}

/// Why a RepoWrite was rejected *before* its body was ever read (see
/// receive.rs's `reject_without_reading_body`). Encoded as the QUIC
/// STOP_SENDING error code, not just the SyncAck's string `error` field —
/// a sender that's still mid-`write_all` when the rejection happens never
/// gets to read that ack (that's the deadlock this fixes: the receiver
/// cuts the sender's blocked write instead of waiting for it to finish),
/// so the stop code is the only way the reason actually reaches the
/// sender. The ack's string field is still set too, for a receiver-side
/// log or a sender that *does* get to read it (e.g. a small file whose
/// body was already fully buffered/flushed before the stop lands).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutRejectReason {
    PledgeExceeded,
    TooLarge,
    InvalidPath,
    DiskFull,
}

impl PutRejectReason {
    pub fn code(self) -> u32 {
        match self {
            Self::PledgeExceeded => 1,
            Self::TooLarge => 2,
            Self::InvalidPath => 3,
            Self::DiskFull => 4,
        }
    }

    /// `None` for code 0 (reserved — an unrelated stream stop, e.g. the
    /// peer just closing the connection, should never be misread as one
    /// of these) or any code this version doesn't recognize.
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::PledgeExceeded),
            2 => Some(Self::TooLarge),
            3 => Some(Self::InvalidPath),
            4 => Some(Self::DiskFull),
            _ => None,
        }
    }

    /// Short, customer-facing explanation — shown on the dashboard next to
    /// a file that's failing to sync, not just logged.
    /// The dashboard's DONT_FIT_REASONS matches the PledgeExceeded and
    /// DiskFull texts to show a calm "don't fit" instead of "failed", so
    /// change them in both places.
    pub fn message(self) -> &'static str {
        match self {
            Self::PledgeExceeded => "your buddy's pledge to you is full",
            Self::TooLarge => "your buddy refused a piece of the backup as too large",
            Self::InvalidPath => "file path was rejected as invalid",
            Self::DiskFull => "your buddy doesn't have enough real disk space left",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HelloResponse {
    pub protocol_version: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncAck {
    pub ok: bool,
    pub error: Option<String>,
}

impl SyncAck {
    pub fn ok() -> Self {
        Self { ok: true, error: None }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self { ok: false, error: Some(msg.into()) }
    }
}

/// Answer to `SyncRequest::DiskStats` — the responder's real, physical
/// filesystem numbers (not a promise): what's actually on disk under its
/// DATA_DIR, plus the sum of what it's pledged out across every buddy it
/// has (including, but not limited to, the one asking). Zeroed out rather
/// than omitted when the host couldn't read disk stats, so a buddy on an
/// unusual filesystem shows up as "unknown" instead of breaking the
/// dashboard that's asking.
#[derive(Debug, Serialize, Deserialize)]
pub struct DiskStatsResponse {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
    pub pledged_out_total_bytes: u64,
}

pub async fn write_frame<T: Serialize>(send: &mut iroh::endpoint::SendStream, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value).context("failed to encode frame")?;
    if bytes.len() > MAX_FRAME_BYTES {
        anyhow::bail!("frame too large to send ({} bytes)", bytes.len());
    }
    send.write_all(&(bytes.len() as u32).to_le_bytes())
        .await
        .context("failed to write frame length")?;
    send.write_all(&bytes).await.context("failed to write frame body")?;
    Ok(())
}

pub async fn read_frame<T: DeserializeOwned>(recv: &mut iroh::endpoint::RecvStream) -> Result<T> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .context("failed to read frame length")?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        anyhow::bail!("peer sent an oversized frame ({len} bytes)");
    }
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.context("failed to read frame body")?;
    serde_json::from_slice(&buf).context("failed to decode frame")
}
