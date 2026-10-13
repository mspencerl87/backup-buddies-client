// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

//! rustic_core's storage backend, pointed at a buddy: every repository file
//! read, write, list and remove becomes a protocol v5 request (repo.rs).
//!
//! rustic calls its backend synchronously, from its own worker threads.
//! Each call here runs the matching request on the tokio runtime with
//! `Handle::block_on`, so a rustic operation must itself run off the async
//! workers (in `spawn_blocking`): `block_on` on a runtime worker panics.
//!
//! One iroh connection carries every call (each request is its own
//! stream). A connection that dropped is reopened and the call tried again;
//! anything else (a missing file, a hash mismatch) would fail the same way
//! twice, so it isn't. Neither is a buddy refusing a write because the
//! pledge or its disk is full: the refusal is kept for the caller to report,
//! like a refused whole-file upload.

use std::future::Future;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayUrl};
use rustic_core::{BytesList, ErrorKind, FileType, Id, ReadBackend, RusticError, RusticResult, WriteBackend};

use crate::protocol::{self, PutRejectReason, RepoFileKind};

/// Tries per call when the connection keeps dropping.
const ATTEMPTS: u64 = 3;

pub(crate) struct BuddyBackend {
    endpoint: Endpoint,
    relay_url: RelayUrl,
    buddy_id: EndpointId,
    rt: tokio::runtime::Handle,
    conn: Mutex<Option<Connection>>,
    refused: Mutex<Option<PutRejectReason>>,
    closed: AtomicBool,
}

impl std::fmt::Debug for BuddyBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BuddyBackend({})", self.buddy_id)
    }
}

impl BuddyBackend {
    /// Call from async code (it keeps the runtime's handle). `conn` is an
    /// already open connection to reuse, if there is one.
    pub(crate) fn new(endpoint: Endpoint, relay_url: RelayUrl, buddy_id: EndpointId, conn: Option<Connection>) -> Self {
        Self {
            endpoint,
            relay_url,
            buddy_id,
            rt: tokio::runtime::Handle::current(),
            conn: Mutex::new(conn),
            refused: Mutex::new(None),
            closed: AtomicBool::new(false),
        }
    }

    /// Why the buddy refused a write, if it did.
    pub(crate) fn refusal(&self) -> Option<PutRejectReason> {
        *self.refused.lock().unwrap()
    }

    /// Makes every later call fail at once. rustic can return an error
    /// while its packer threads are still writing other packs (seen in
    /// testing after a pledge refusal); once the cycle is over, those must
    /// not reconnect, retry or overlap the next cycle.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    /// The connection in use, for metering.
    pub(crate) fn connection_now(&self) -> Option<Connection> {
        self.conn.lock().unwrap().clone()
    }

    async fn connection(&self) -> Result<Connection> {
        if let Some(conn) = self.conn.lock().unwrap().as_ref().filter(|c| c.close_reason().is_none()) {
            return Ok(conn.clone());
        }
        let addr = EndpointAddr::new(self.buddy_id).with_relay_url(self.relay_url.clone());
        let conn = self.endpoint.connect(addr, protocol::ALPN).await.map_err(protocol::explain_connect_error)?;
        *self.conn.lock().unwrap() = Some(conn.clone());
        Ok(conn)
    }

    fn call<T, F, Fut>(&self, what: &str, request: F) -> RusticResult<T>
    where
        F: Fn(Connection) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        // After a refusal nothing else will fit either: fail fast rather
        // than send packs the buddy would refuse one by one.
        let stop = if self.closed.load(Ordering::Relaxed) {
            Some("this backup cycle is over")
        } else {
            self.refusal().map(PutRejectReason::message)
        };
        if let Some(why) = stop {
            return Err(RusticError::new(ErrorKind::Backend, "Request to the buddy skipped: {why}.")
                .attach_context("why", why.to_string()));
        }
        let result = self.rt.block_on(async {
            let mut attempt = 0;
            loop {
                attempt += 1;
                let err = match self.connection().await {
                    Ok(conn) => match request(conn.clone()).await {
                        Ok(value) => return Ok(value),
                        Err(err) => {
                            if let Some(reason) = refusal_in(&err) {
                                *self.refused.lock().unwrap() = Some(reason);
                                return Err(err);
                            }
                            if conn.close_reason().is_none() {
                                return Err(err);
                            }
                            err
                        }
                    },
                    Err(err) => err,
                };
                if attempt >= ATTEMPTS {
                    return Err(err);
                }
                tracing::debug!(?err, attempt, "repository request to buddy failed — reconnecting");
                tokio::time::sleep(Duration::from_secs(2 * attempt)).await;
            }
        });
        result.map_err(|err| {
            RusticError::with_source(ErrorKind::Backend, "Request to the buddy failed: {what}.", err)
                .attach_context("what", what.to_string())
        })
    }
}

/// The buddy refusing a write, from its STOP_SENDING code or (when the
/// write was small enough to be sent before the stop landed) its ack.
fn refusal_in(err: &anyhow::Error) -> Option<PutRejectReason> {
    let all = (1..=4).filter_map(PutRejectReason::from_code);
    err.chain().find_map(|cause| {
        if let Some(iroh::endpoint::WriteError::Stopped(code)) = cause.downcast_ref::<iroh::endpoint::WriteError>() {
            return PutRejectReason::from_code(code.into_inner());
        }
        let text = cause.to_string();
        all.clone().find(|r| text.contains(r.message()))
    })
}

fn kind_of(tpe: FileType) -> RepoFileKind {
    match tpe {
        FileType::Config => RepoFileKind::Config,
        FileType::Index => RepoFileKind::Index,
        FileType::Key => RepoFileKind::Key,
        FileType::Snapshot => RepoFileKind::Snapshot,
        FileType::Pack => RepoFileKind::Pack,
    }
}

fn hex(id: &Id) -> String {
    id.to_hex().to_string()
}

impl ReadBackend for BuddyBackend {
    fn location(&self) -> String {
        format!("buddy {}", self.buddy_id.fmt_short())
    }

    fn list_with_size(&self, tpe: FileType) -> RusticResult<Vec<(Id, u32)>> {
        let files = self.call("list", |conn| async move { crate::repo::list(&conn, kind_of(tpe)).await })?;
        files
            .into_iter()
            .map(|f| Ok((f.id.parse::<Id>()?, u32::try_from(f.size).unwrap_or(u32::MAX))))
            .collect()
    }

    fn read_full(&self, tpe: FileType, id: &Id) -> RusticResult<Bytes> {
        let id = hex(id);
        self.call("read", |conn| {
            let id = id.clone();
            async move { crate::repo::read(&conn, kind_of(tpe), &id, 0, None).await }
        })
        .map(Bytes::from)
    }

    fn read_partial(&self, tpe: FileType, id: &Id, _cacheable: bool, offset: u32, length: u32) -> RusticResult<Bytes> {
        let id = hex(id);
        self.call("read", |conn| {
            let id = id.clone();
            async move { crate::repo::read(&conn, kind_of(tpe), &id, offset.into(), Some(length.into())).await }
        })
        .map(Bytes::from)
    }

    fn warmup_path(&self, tpe: FileType, id: &Id) -> String {
        format!("{tpe:?}/{}", hex(id))
    }
}

impl WriteBackend for BuddyBackend {
    fn write_bytes(&self, tpe: FileType, id: &Id, _cacheable: bool, content: BytesList) -> RusticResult<()> {
        let id = hex(id);
        // A pack is at most tens of MB; one buffer keeps the wire call simple.
        let data: Vec<u8> = content.into_vec().concat();
        self.call("write", |conn| {
            let (id, data) = (id.clone(), &data);
            async move { crate::repo::write(&conn, kind_of(tpe), &id, data).await }
        })
    }

    fn remove(&self, tpe: FileType, id: &Id, _cacheable: bool) -> RusticResult<()> {
        let id = hex(id);
        self.call("remove", |conn| {
            let id = id.clone();
            async move { crate::repo::remove(&conn, kind_of(tpe), &id).await }
        })
    }
}
