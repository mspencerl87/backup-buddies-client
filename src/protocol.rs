// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

// One protocol name for every client version. Newer features are found by
// asking (SyncRequest::Hello), not by a new ALPN: an ALPN a peer doesn't
// support makes iroh connections hang until timeout rather than fail fast,
// which would break every pairing where one buddy updated first.
pub const ALPN: &[u8] = b"backup-buddies/sync/1";

/// This client's protocol version, reported in HelloResponse.
/// 2 (client 0.5.0): PutStream.
/// 3 (client 0.8.0): PutResumable.
/// 4 (client 0.9.0): PurgeDeleted.
pub const PROTOCOL_VERSION: u32 = 4;

/// Largest file sent to a buddy whose client predates PutStream: the old
/// Put needs the whole file's hash before sending, so the encrypted file is
/// held in memory first. Bigger files wait until the buddy updates.
pub const LEGACY_PUT_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// Largest single file accepted. Files stream in bounded memory now, so
/// this is only a sanity bound; pledges and the real-disk floor are what
/// actually limit how much a buddy can store.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024 * 1024; // 1 TiB

pub fn explain_connect_error(err: impl std::fmt::Display) -> anyhow::Error {
    anyhow::anyhow!("failed to connect to buddy: {err}")
}

// Every exchange on a stream starts with one framed SyncRequest, answered
// with one framed SyncAck (Ping/Put/Delete), a ListResponse (List), or a
// SyncAck followed by raw bytes (Get). Framing is a 4-byte little-endian
// length prefix followed by that many bytes of JSON — simple, and keeps
// control messages clearly separated from the raw file bytes that follow
// some of them on the same stream.
const MAX_FRAME_BYTES: usize = 1024 * 1024; // control messages are tiny; generous headroom

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum SyncRequest {
    /// No backup work to do this cycle — just prove the connection still
    /// works. Same purpose the old test-payload protocol served.
    Ping,
    /// "Here's a new/changed file." Followed immediately on the stream by
    /// exactly `ciphertext_len` raw bytes — not framed, since the header
    /// already states the length.
    Put {
        path: String,
        ciphertext_len: u64,
        ciphertext_sha256: String,
    },
    /// Protocol v2's upload: like Put, but the SHA-256 isn't known until
    /// the file has been encrypted and sent, so it follows the
    /// `ciphertext_len` raw bytes as a framed `PutTrailer`.
    PutStream { path: String, ciphertext_len: u64 },
    /// Protocol v3's upload for big files: like PutStream, but an upload
    /// cut off partway can carry on where it stopped. The receiver keeps
    /// the partial bytes under `upload_id` and answers with a
    /// PutResumeReply saying how many it already has; the sender then sends
    /// only the rest, followed by a PutTrailer for the *whole* file, and
    /// gets a SyncAck. Resuming only works because the sender kept the
    /// exact ciphertext it started with (age encrypts with a fresh random
    /// key each time, so re-encrypting would give different bytes) — a new
    /// encryption always gets a new `upload_id`.
    PutResumable { path: String, upload_id: String, ciphertext_len: u64 },
    /// Protocol v2's List: the same file list, sent as a series of
    /// ListChunk frames (LIST_CHUNK_ENTRIES each, last one `done: true`)
    /// instead of one frame — a single frame caps out around 10,000 files
    /// (MAX_FRAME_BYTES). Older clients don't know it and drop the stream;
    /// the caller then falls back to List.
    ListStream,
    /// "Which protocol version do you speak?" Answered with HelloResponse.
    /// A client older than 0.5.0 can't parse this and drops the stream —
    /// which is itself the answer: version 1.
    Hello,
    /// "Forget this file" — frees up the sender's pledge usage with us.
    /// Idempotent: deleting something already gone is not an error.
    Delete { path: String },
    /// "What do you have backed up for me?" Answered with ListResponse.
    /// Scoped to the connecting peer's own authenticated node id — a
    /// buddy can only ever list/fetch what *they themselves* stored with
    /// us, never another buddy's data (see receive.rs).
    List,
    /// "Send me this one file's ciphertext back." Answered with a
    /// SyncAck (ok:false if not found), or on success a SyncAck{ok:true}
    /// immediately followed by the raw ciphertext bytes.
    Get { path: String },
    /// "What does your disk actually look like?" — real filesystem space
    /// plus how much of it you've committed across every buddy, not just
    /// what you've pledged me. Answered with DiskStatsResponse. Lets each
    /// side's dashboard show the other's real numbers instead of just
    /// trusting the pledge they agreed to, so an over-pledged or
    /// nearly-full buddy is visible before it becomes a failed backup.
    DiskStats,
    /// "What old copies of this file do you still have?" — every time a
    /// path is overwritten or deleted, the previous content is kept as a
    /// numbered backup rather than discarded (see receive.rs's
    /// rotate_versions). Answered with ListVersionsResponse.
    ListVersions { path: String },
    /// "Send me backup slot N of this file." Same response shape as Get:
    /// a SyncAck, then on success the raw ciphertext bytes.
    GetVersion { path: String, version: u32 },
    /// "Remove the backup copies of this file I deleted, for good" — the
    /// dashboard's "Delete permanently". Answered with a SyncAck. Refused
    /// while a live file still exists at `path`, so it can only ever take
    /// away copies of something the sender already deleted.
    PurgeDeleted { path: String },
}

/// Why a Put was rejected *before* its body was ever read (see
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
            Self::TooLarge => "file is larger than the 1 TB per-file limit",
            Self::InvalidPath => "file path was rejected as invalid",
            Self::DiskFull => "your buddy doesn't have enough real disk space left",
        }
    }
}

pub const LIST_CHUNK_ENTRIES: usize = 5000;

#[derive(Debug, Serialize, Deserialize)]
pub struct ListChunk {
    pub files: Vec<ListEntry>,
    pub done: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HelloResponse {
    pub protocol_version: u32,
}

/// The receiver's answer to PutResumable, before any file bytes: `offset`
/// is how many bytes of this upload it already holds (0 for a new one).
/// On a refusal `offset` is None and `reject_code` is the PutRejectReason
/// code, also sent as STOP_SENDING like any other refusal.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PutResumeReply {
    #[serde(default)]
    pub offset: Option<u64>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub reject_code: Option<u64>,
}

/// Sent after a PutStream's bytes.
#[derive(Debug, Serialize, Deserialize)]
pub struct PutTrailer {
    pub ciphertext_sha256: String,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct ListEntry {
    pub path: String,
    pub size: u64,
    /// True when this path has no live file anymore — it was deleted, and
    /// what's left is only a backup slot under `.versions/` (see
    /// `rotate_versions` in receive.rs). `size` for a deleted entry is the
    /// size of its newest surviving version, not a live file. Lets the
    /// dashboard's file browser still show (and offer History/restore-a-
    /// version for) a file the person deleted, instead of it silently
    /// disappearing from the list the moment there's no live copy.
    #[serde(default)]
    pub deleted: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListResponse {
    pub files: Vec<ListEntry>,
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

/// One backed-up previous copy of a file. `version: 1` is the most
/// recently replaced/deleted content, counting up to however many backup
/// slots this host keeps (see receive.rs::MAX_BACKUP_VERSIONS) — the
/// live/current copy (if it still exists) is not included here, it's what
/// List/Get already report.
#[derive(Debug, Serialize, Deserialize)]
pub struct VersionEntry {
    pub version: u32,
    pub size: u64,
    /// When this became a backup copy (client 0.8.2+; before that, when it
    /// was uploaded).
    pub modified_unix: Option<u64>,
    /// When the buddy will remove it for good (VERSION_RETENTION_DAYS).
    /// None from buddies older than 0.8.2, which keep copies forever.
    #[serde(default)]
    pub expires_unix: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListVersionsResponse {
    pub versions: Vec<VersionEntry>,
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
