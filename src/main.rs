// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

mod backup;
mod bandwidth;
mod dashboard;
mod manifest;
mod netinfo;
mod protocol;
mod receive;
mod crypto;
#[cfg(test)]
mod e2e_tests;
mod index;
mod restore;
mod update_check;

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use age::secrecy::SecretString;
use anyhow::{Context, Result};
use iroh::{
    endpoint::presets::Minimal, Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey,
};
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use serde::Deserialize;

use receive::{PledgeBook, PledgeState};

// Default for SCAN_INTERVAL_SECS: how often each buddy's backup cycle runs.
// A cycle on an unchanged folder is now a metadata-only listing (see
// backup.rs), so this is cheap even for large folders; people with very
// large folders, or on slow network mounts, can still set it higher.
const DEFAULT_SCAN_INTERVAL_SECS: u64 = 30;

struct Config {
    api_url: String,
    device_token: String,
    passphrase: SecretString,
    relay_url: RelayUrl,
    // Config/state only: this device's identity key, per-buddy manifests,
    // and the usage/bandwidth ledgers — all small. Kept separate from the
    // two dirs below so a user's data drive never gets the client's own
    // files mixed into it, and config can live next to docker-compose.yml.
    data_dir: PathBuf,
    // What buddies store with us: BUDDY_FILES_DIR/<their node id>/...
    // (encrypted, unreadable to us). Usually the big one — meant to point
    // at a dedicated folder on whatever drive has the space. Defaults to
    // DATA_DIR/received, the pre-split layout, so an existing install that
    // doesn't set it keeps working unchanged.
    buddy_files_dir: PathBuf,
    // Where restores from the dashboard (and the `restore` CLI's default)
    // land: RESTORE_DIR/<their node id>/... Never inside BACKUP_DIR, which
    // is mounted read-only. Defaults to DATA_DIR/restored (pre-split).
    restore_dir: PathBuf,
    // RESTORE_DIR as the person knows it on their own machine, for the
    // dashboard's "Restored N file(s) to …" line — the container path
    // (/restored) means nothing to someone looking in their file manager.
    // See host_path_for_display.
    restore_dir_display: String,
    // Where the real files to back up live. Optional — a client that's
    // only ever meant to receive (e.g. this machine has lots of disk and
    // is mainly someone else's buddy) doesn't need one. None here means
    // the periodic backup cycle is skipped entirely, but this device still
    // accepts and stores whatever its buddy sends it.
    backup_dir: Option<PathBuf>,
    // Local status/restore dashboard's bind address. Built from
    // DASHBOARD_PORT (0.0.0.0:<that port>) rather than a hardcoded 8080 —
    // with network_mode: host (see docker-compose.yml) there's no Docker
    // port-mapping layer to translate a fixed internal port to a chosen
    // host one, so the app itself has to bind the real port directly.
    // This matters for running more than one device's client on the same
    // host (see DASHBOARD_PORT's own doc comment below): each needs a
    // distinct DASHBOARD_PORT, same requirement as SYNC_PORT already has.
    // DASHBOARD_BIND remains as an escape hatch to override the full
    // address (e.g. to bind loopback-only) when DASHBOARD_PORT alone
    // isn't enough.
    dashboard_bind: String,
    // How long since a buddy's last *successful* cycle before the
    // dashboard calls them stale rather than just "last synced a while
    // ago" — see dashboard.rs's stale computation. 30s between cycles
    // means a handful of transient failures shouldn't trip this; it's
    // meant to catch a buddy that's actually stuck.
    stale_after_secs: u64,
    // SCAN_INTERVAL_SECS (default 30): seconds between backup cycles.
    scan_interval_secs: u64,
    // The UDP port iroh binds for the actual sync traffic (separate from
    // DASHBOARD_BIND's TCP port above). Fixed and configurable, rather
    // than the random free port iroh picks by default, specifically so
    // docker-compose.yml can publish it — see the `ports:` entry there.
    // Without a published UDP port, NAT means this device can never
    // receive an inbound hole-punch attempt, so direct (peer-to-peer)
    // connections are impossible and every byte relays, even between two
    // buddies who'd otherwise connect directly fine. Forwarding this port
    // on a home router is still optional — nothing breaks without it,
    // every transfer just goes through the relay instead, same as before
    // this existed.
    sync_port: u16,
}

impl Config {
    fn from_env() -> Result<Self> {
        let api_url = std::env::var("API_URL").context("API_URL env var is required")?;
        let device_token =
            std::env::var("DEVICE_TOKEN").context("DEVICE_TOKEN env var is required")?;
        let passphrase = std::env::var("BACKUP_PASSPHRASE")
            .context("BACKUP_PASSPHRASE env var is required — this never leaves your machine")?;
        if passphrase.len() < 12 {
            tracing::warn!(
                "BACKUP_PASSPHRASE is under 12 characters — a short passphrase is much easier to \
                 guess, and there's no way to recover your buddy's copy of your data if it's ever \
                 lost or cracked (there's no \"forgot passphrase\" flow by design)"
            );
        }
        // Meant for one restart after deliberately emptying the folder, but
        // easy to leave on (seen on a test device), which silently disables
        // the guard against an unmounted drive wiping the buddy's copy.
        if backup::allow_empty_backup_dir() {
            tracing::warn!(
                "ALLOW_EMPTY_BACKUP_DIR is on: if the drive with your files isn't mounted, its empty                  folder will be mirrored to your buddy as \"everything deleted\". Remove it from .env                  once your deliberate cleanup has synced."
            );
        }
        let relay_url = std::env::var("RELAY_URL")
            .unwrap_or_else(|_| "https://relay.filegarden.net".to_string())
            .parse()
            .context("RELAY_URL is not a valid URL")?;
        let data_dir: PathBuf = std::env::var("DATA_DIR").unwrap_or_else(|_| "/data".to_string()).into();
        let buddy_files_dir = std::env::var("BUDDY_FILES_DIR")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("received"));
        let restore_dir = std::env::var("RESTORE_DIR")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("restored"));
        let restore_dir_display = host_path_for_display(&restore_dir);
        let backup_dir = std::env::var("BACKUP_DIR").ok().map(PathBuf::from);
        let dashboard_port = std::env::var("DASHBOARD_PORT")
            .ok()
            .map(|s| s.parse::<u16>().context("DASHBOARD_PORT must be a valid port number (1-65535)"))
            .transpose()?
            .unwrap_or(8080);
        let dashboard_bind = std::env::var("DASHBOARD_BIND")
            .unwrap_or_else(|_| format!("0.0.0.0:{dashboard_port}"));
        let scan_interval_secs = std::env::var("SCAN_INTERVAL_SECS")
            .ok()
            .map(|s| {
                s.trim()
                    .parse::<u64>()
                    .ok()
                    .filter(|&n| n >= 5)
                    .context("SCAN_INTERVAL_SECS must be a whole number of seconds, at least 5")
            })
            .transpose()?
            .unwrap_or(DEFAULT_SCAN_INTERVAL_SECS);
        // A buddy only counts as stale after missing several cycles, so a
        // long scan interval doesn't make every buddy look stale between
        // cycles.
        let stale_after_secs = std::env::var("STALE_AFTER_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(600u64.max(scan_interval_secs * 3));
        let sync_port = std::env::var("SYNC_PORT")
            .ok()
            .map(|s| s.parse().context("SYNC_PORT must be a valid port number (1-65535)"))
            .transpose()?
            .unwrap_or(11235);

        Ok(Self {
            api_url,
            device_token,
            passphrase: SecretString::from(passphrase),
            relay_url,
            data_dir,
            buddy_files_dir,
            restore_dir,
            restore_dir_display,
            backup_dir,
            dashboard_bind,
            stale_after_secs,
            scan_interval_secs,
            sync_port,
        })
    }

    // Fails loud and early, before any of the long-running loops start,
    // rather than letting a bad config surface later as a confusing
    // runtime symptom — an empty-looking backup cycle because BACKUP_DIR
    // doesn't actually exist, or a cryptic connection error because
    // API_URL has a typo in it.
    async fn validate(&mut self) -> Result<()> {
        if let Some(backup_dir) = &self.backup_dir {
            let meta = tokio::fs::metadata(backup_dir).await.with_context(|| {
                format!(
                    "BACKUP_DIR is set to {} but it doesn't exist or isn't readable from inside the container \
                     — check the BACKUP_DIR_HOST bind mount in docker-compose.yml",
                    backup_dir.display()
                )
            })?;
            if !meta.is_dir() {
                anyhow::bail!("BACKUP_DIR ({}) exists but isn't a directory", backup_dir.display());
            }
        }

        reqwest::Url::parse(&self.api_url)
            .with_context(|| format!("API_URL ({}) isn't a valid URL", self.api_url))?;

        // DATA_DIR itself is create_dir_all'd right after this runs (which
        // already fails loudly on its own if that's not possible) — this
        // additionally proves the directory is actually *writable*, not
        // just creatable, by round-tripping a small probe file. A
        // read-only bind mount would otherwise only surface much later, as
        // a failed iroh_secret_key write.
        // Same check for BUDDY_FILES_DIR and RESTORE_DIR, which can each be
        // their own bind mount (a different drive, a read-only mount by
        // mistake) and would otherwise only fail on the first incoming file
        // or the first restore.
        for (name, dir) in [
            ("DATA_DIR", &self.data_dir),
            ("BUDDY_FILES_DIR", &self.buddy_files_dir),
            ("RESTORE_DIR", &self.restore_dir),
        ] {
            ensure_writable_dir(name, dir).await?;
        }

        self.check_pre_split_layout().await?;
        self.check_buddy_files_identity().await?;
        Ok(())
    }

    // Guards against BUDDY_FILES_DIR being the wrong folder — most often a
    // drive that isn't mounted yet when the container starts, in which case
    // Docker binds the empty mount-point folder instead and incoming buddy
    // files would land on the OS disk (then vanish from view once the real
    // drive mounts over them). The first time a folder is used, the client
    // writes a random ID into it (BUDDY_FILES_MARKER) and keeps a copy in
    // DATA_DIR (BUDDY_FILES_ID_RECORD); every later start checks they still
    // match.
    //
    //   record   marker      →
    //   none     none        first run (or an install from before this
    //                        check): stamp the folder, keep the record
    //   none     present     config was reset, folder kept: adopt its ID
    //   X        X           fine
    //   X        none        folder isn't the one we were using (unmounted
    //                        drive, wrong path) → refuse to start
    //   X        Y           a different buddy-files folder → refuse
    //
    // To start over on purpose with a new, empty folder, delete
    // DATA_DIR/buddy-files-id (the refusal message says so).
    async fn check_buddy_files_identity(&self) -> Result<()> {
        let record_path = self.data_dir.join(BUDDY_FILES_ID_RECORD);
        let marker_path = self.buddy_files_dir.join(BUDDY_FILES_MARKER);
        // The ID is the first line; the marker file also carries a comment
        // explaining what it is.
        let read_id = |p: PathBuf| async move {
            tokio::fs::read_to_string(&p)
                .await
                .ok()
                .and_then(|s| s.lines().next().map(|l| l.trim().to_string()))
                .filter(|s| !s.is_empty())
        };
        let record = read_id(record_path.clone()).await;
        let marker = read_id(marker_path.clone()).await;

        match (record, marker) {
            (Some(expected), Some(found)) if expected == found => Ok(()),
            (Some(expected), found) => {
                let what = match found {
                    None => "has no Backup Buddies marker — it isn't the folder this device has been storing buddy files in",
                    Some(_) => "belongs to a different Backup Buddies setup than this device's",
                };
                anyhow::bail!(
                    "BUDDY_FILES_DIR ({}) {what}. If that folder is on a drive or network share, it may not be \
                     mounted yet — mount it and start the client again. If you moved the buddy files, point \
                     BUDDY_FILES_DIR_HOST at the new folder. To deliberately start over with a new, empty \
                     folder (your buddies will re-send what they had stored here), delete {} and start again. \
                     (Expected marker {expected}.)",
                    self.buddy_files_dir.display(),
                    record_path.display(),
                );
            }
            (None, Some(found)) => {
                tokio::fs::write(&record_path, format!("{found}\n"))
                    .await
                    .with_context(|| format!("can't write {}", record_path.display()))?;
                Ok(())
            }
            (None, None) => {
                // Only needs to be unique per folder, not secret.
                let id = {
                    use sha2::{Digest, Sha256};
                    let seed = format!(
                        "{:?}|{}|{}",
                        std::time::SystemTime::now(),
                        std::process::id(),
                        self.buddy_files_dir.display()
                    );
                    hex::encode(&Sha256::digest(seed.as_bytes())[..16])
                };
                tokio::fs::write(
                    &marker_path,
                    format!(
                        "{id}\n# Backup Buddies: this folder holds files your buddies store with you.\n\
                         # Don't delete this file — the client uses it to check this folder is mounted.\n"
                    ),
                )
                .await
                .with_context(|| format!("can't write {}", marker_path.display()))?;
                tokio::fs::write(&record_path, format!("{id}\n"))
                    .await
                    .with_context(|| format!("can't write {}", record_path.display()))?;
                Ok(())
            }
        }
    }

    // Before BUDDY_FILES_DIR / RESTORE_DIR existed, both lived inside
    // DATA_DIR (as received/ and restored/). An existing install that picks
    // up the new docker-compose.yml (e.g. via `install.sh --update`, which
    // keeps .env) gets BUDDY_FILES_DIR pointed at a fresh, empty folder
    // while its buddies' files are still in DATA_DIR/received. Starting on
    // the empty folder would make those backups look missing (and
    // usage.json would still count them against each pledge), so:
    //   - new folder empty, old one has files -> keep using the old
    //     location, and warn with how to move them;
    //   - both have files -> refuse to start: we can't tell which is real;
    //   - old one empty -> tidy it away so DATA_DIR holds config only.
    // Files are never moved automatically: rename doesn't work across bind
    // mounts (even on the same disk), and silently copying what could be
    // terabytes at startup isn't something to do behind someone's back.
    async fn check_pre_split_layout(&mut self) -> Result<()> {
        let legacy_received = self.data_dir.join("received");
        let received_moved = !same_dir(&legacy_received, &self.buddy_files_dir).await;
        if received_moved && dir_has_entries(&legacy_received).await {
            if dir_has_entries(&self.buddy_files_dir).await {
                anyhow::bail!(
                    "buddy files exist in both {} (the old location) and {} (BUDDY_FILES_DIR) — the client \
                     won't start until there's only one. Stop the client and, on the host, move everything \
                     from <DATA_DIR_HOST>/received/ into <BUDDY_FILES_DIR_HOST>/, merging any per-buddy folders.",
                    legacy_received.display(),
                    self.buddy_files_dir.display()
                );
            }
            tracing::warn!(
                using = %legacy_received.display(),
                configured = %self.buddy_files_dir.display(),
                "buddy files are still in the old location inside DATA_DIR, so the client is using them there for now. \
                 To move them to their own folder: stop the client, then on the host move everything from \
                 <DATA_DIR_HOST>/received/ into <BUDDY_FILES_DIR_HOST>/ (e.g. `mv data/received/* buddy-files/`), \
                 and start it again"
            );
            let _ = tokio::fs::remove_dir(&self.buddy_files_dir).await; // only if empty; tidy the unused mount point
            self.buddy_files_dir = legacy_received;
            return self.check_legacy_restored().await;
        }
        // Empty leftover from the old layout — tidy it away so DATA_DIR
        // holds config only. remove_dir only succeeds on an empty dir.
        if received_moved {
            // `mv data/received/* newfolder/` skips dotfiles, so the
            // buddy-files marker (see check_buddy_files_identity) can be
            // left behind. Carry it over — but only once the new folder
            // actually has buddy files in it: if it's empty, it may be an
            // unmounted drive, and stamping it would defeat that check.
            let legacy_marker = legacy_received.join(BUDDY_FILES_MARKER);
            let new_marker = self.buddy_files_dir.join(BUDDY_FILES_MARKER);
            if tokio::fs::metadata(&legacy_marker).await.is_ok() {
                if tokio::fs::metadata(&new_marker).await.is_err()
                    && dir_has_entries(&self.buddy_files_dir).await
                {
                    tokio::fs::copy(&legacy_marker, &new_marker)
                        .await
                        .with_context(|| format!("can't write {}", new_marker.display()))?;
                }
                if tokio::fs::metadata(&new_marker).await.is_ok() {
                    let _ = tokio::fs::remove_file(&legacy_marker).await;
                }
            }
            let _ = tokio::fs::remove_dir(&legacy_received).await;
        }

        self.check_legacy_restored().await
    }

    // Old restores are the user's own output, not something the client
    // depends on — just point at them rather than blocking startup.
    async fn check_legacy_restored(&self) -> Result<()> {
        let legacy_restored = self.data_dir.join("restored");
        if !same_dir(&legacy_restored, &self.restore_dir).await {
            if dir_has_entries(&legacy_restored).await {
                tracing::warn!(
                    old = %legacy_restored.display(),
                    new = %self.restore_dir.display(),
                    "files restored before RESTORE_DIR was set are still in the old location — new restores go to the new one; move or delete the old ones whenever convenient"
                );
            } else {
                let _ = tokio::fs::remove_dir(&legacy_restored).await;
            }
        }
        Ok(())
    }
}

// Inside the container, RESTORE_DIR is just /restored — the host folder it's
// mounted from isn't visible to us. But docker-compose.yml loads .env with
// env_file, so whatever the person set there (RESTORE_DIR_HOST, or
// DATA_DIR_HOST for the pre-split layout) is in our environment too — and
// it's the path they'd recognise, since they wrote it. Falls back to the
// compose file's defaults when those aren't set, and to the real path when
// not running in Docker at all.
fn host_path_for_display(restore_dir: &Path) -> String {
    let var = |name: &str| std::env::var(name).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    if !Path::new("/.dockerenv").exists() {
        return restore_dir.display().to_string();
    }
    let host = if var("RESTORE_DIR").is_some() {
        var("RESTORE_DIR_HOST").unwrap_or_else(|| "./restored".to_string())
    } else {
        // Old compose file: restores live under DATA_DIR/restored.
        format!("{}/restored", var("DATA_DIR_HOST").unwrap_or_else(|| "./data".to_string()).trim_end_matches('/'))
    };
    host.trim_end_matches('/').to_string()
}

// The host folder behind one of the container's mounts (/backup,
// /buddy-files), when .env names it — env_file passes *_DIR_HOST through,
// same as RESTORE_DIR_HOST above. The setup page's newer compose file puts
// host paths in docker-compose.yml instead, which we can't see; then this
// is None. Outside Docker the path is already the real one.
pub fn host_dir(dir: &Path, host_var: &str) -> Option<String> {
    if !Path::new("/.dockerenv").exists() {
        return Some(dir.display().to_string());
    }
    std::env::var(host_var).ok().map(|s| s.trim().trim_end_matches('/').to_string()).filter(|s| !s.is_empty())
}

/// `host_dir`, or the container path plus where to find the real one —
/// for messages telling someone which folder to go and look at.
pub fn host_dir_label(dir: &Path, host_var: &str) -> String {
    host_dir(dir, host_var)
        .unwrap_or_else(|| format!("{} (the folder mapped to it in docker-compose.yml)", dir.display()))
}

// See Config::check_buddy_files_identity.
const BUDDY_FILES_MARKER: &str = ".backup-buddies-id";
const BUDDY_FILES_ID_RECORD: &str = "buddy-files-id";

async fn ensure_writable_dir(name: &str, dir: &Path) -> Result<()> {
    tokio::fs::create_dir_all(dir)
        .await
        .with_context(|| format!("can't create {name} ({})", dir.display()))?;
    let probe = dir.join(".write-test");
    tokio::fs::write(&probe, b"ok")
        .await
        .with_context(|| format!("{name} ({}) isn't writable — check its bind mount in docker-compose.yml", dir.display()))?;
    let _ = tokio::fs::remove_file(&probe).await;
    Ok(())
}

// True if both paths are the same directory — compared by device + inode,
// not by path, because the same host folder can show up at two different
// paths inside the container (e.g. BUDDY_FILES_DIR_HOST pointed at the old
// DATA_DIR_HOST/received, which is then visible both as /buddy-files and
// as /data/received). Equal paths count as the same even if neither
// exists yet.
async fn same_dir(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    if a == b {
        return true;
    }
    match (tokio::fs::metadata(a).await, tokio::fs::metadata(b).await) {
        (Ok(ma), Ok(mb)) => ma.dev() == mb.dev() && ma.ino() == mb.ino(),
        _ => false,
    }
}

// Ignores the buddy-files marker, which on its own doesn't make a folder
// "have buddy files" (see check_buddy_files_identity).
async fn dir_has_entries(dir: &Path) -> bool {
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else { return false };
    while let Ok(Some(entry)) = entries.next_entry().await {
        if entry.file_name() != BUDDY_FILES_MARKER {
            return true;
        }
    }
    false
}

#[derive(Deserialize)]
struct BuddyDevice {
    account_id: String,
    iroh_node_id: Option<String>,
    label: Option<String>,
    // node-postgres serializes BIGINT as a JSON string (to avoid precision
    // loss past 2^53), not a number — hence String here, parsed below.
    pledged_bytes: Option<String>,
}

#[derive(Deserialize)]
struct BuddiesResponse {
    buddy_devices: Vec<BuddyDevice>,
    // Set by the API when this account's relay syncing has been paused
    // (today: a Stripe payment that failed after retries were exhausted —
    // see apps/api/src/routes/stripe-webhook.js). `#[serde(default)]` so an
    // older API that doesn't send this field yet still deserializes fine,
    // defaulting to "not paused" rather than failing the whole poll.
    #[serde(default)]
    paused: bool,
    // This device's own label, as set in the web dashboard's Devices card
    // (devices.js's GET /devices/me/buddies). `#[serde(default)]` for the
    // same reason as `paused` above; None until the first successful poll,
    // or if the device was never given a label.
    #[serde(default)]
    self_label: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Default to info for this crate's own logs, but quiet down
    // swarm-discovery's own chatty internal logging (e.g. "no addresses
    // for peer, not announcing" during normal startup, before this
    // device's own address is resolved yet) — it's noise, not signal,
    // for anyone reading these logs. RUST_LOG, if set, overrides this
    // entirely rather than layering on top of it.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(
            |_| tracing_subscriber::EnvFilter::new("info,swarm_discovery=warn"),
        ))
        .init();
    let mut config = Config::from_env()?;
    config.validate().await?;

    // DATA_DIR, BUDDY_FILES_DIR and RESTORE_DIR were all created (and
    // proven writable) by validate() above.

    // The User-Agent carries this build's version (Cargo.toml) on every API
    // call, so the server can record which version each device runs and the
    // web dashboard can tell the user when an update is available (see
    // apps/api/src/routes/devices.js). Bump Cargo.toml's version whenever
    // you ship a client change people should update to.
    let http = reqwest::Client::builder()
        .user_agent(concat!("backup-buddies-client/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build HTTP client")?;

    // The encryption key is salted with this device's account id (see
    // crypto.rs), so look that up first.
    let account_id = load_account_id(&http, &config).await?;

    // Derive the file-encryption key from the passphrase (~1s, once) and
    // open the on-disk index (importing old JSON manifests on first run).
    crypto::init(&config.passphrase, &account_id).context("failed to derive encryption key from BACKUP_PASSPHRASE")?;
    index::open(&config.data_dir).context("failed to open the index in DATA_DIR")?;
    receive::clear_incoming(&config.buddy_files_dir).await;
    backup::init_spool(&config.data_dir).await;

    // Remove buddies' backup copies (replaced or deleted content) once
    // they're VERSION_RETENTION_DAYS old: now, then daily.
    {
        let buddy_files_dir = config.buddy_files_dir.clone();
        tokio::spawn(async move {
            loop {
                let (files, bytes) = receive::expire_versions(&buddy_files_dir).await;
                if files > 0 {
                    tracing::info!(
                        files,
                        bytes,
                        days = receive::VERSION_RETENTION_DAYS,
                        "removed buddies' backup copies past the retention period"
                    );
                }
                tokio::time::sleep(Duration::from_secs(24 * 60 * 60)).await;
            }
        });
    }

    let secret_key = load_or_generate_secret_key(&config.data_dir).await?;
    let endpoint_id = secret_key.public();

    // Bind to a fixed, known port on both IP families instead of the
    // random free port iroh picks by default — clear_ip_transports()
    // first, since the builder otherwise already has its own default
    // 0.0.0.0:0 / [::]:0 binds queued up, which would leave this
    // listening on *two* sockets per family rather than replacing them.
    // See sync_port's doc comment on Config for why a fixed port matters:
    // docker-compose.yml can only publish a UDP port it knows ahead of
    // time, and a published port is what makes direct connections
    // possible at all.
    // Same idea as Syncthing's local discovery: broadcast/listen on the LAN
    // (mDNS, via swarm-discovery) so two buddies on the same local network
    // — two NAS boxes in the same house, say — find each other's private
    // address and connect directly over the LAN, never touching the relay
    // or caring about the router's NAT/hairpin behavior at all. Built
    // up-front (rather than via the builder's `.address_lookup()` taking
    // just a builder type) so we keep a handle to subscribe to its
    // discovery events below, for visibility in the logs.
    let mdns = MdnsAddressLookup::builder()
        .build(endpoint_id)
        .context("failed to start local-network (mDNS) address lookup")?;

    let endpoint = Endpoint::builder(Minimal)
        .secret_key(secret_key)
        .alpns(vec![protocol::ALPN.to_vec()])
        .relay_mode(RelayMode::custom([config.relay_url.clone()]))
        .clear_ip_transports()
        .bind_addr(format!("0.0.0.0:{}", config.sync_port))
        .context("failed to configure IPv4 sync port")?
        // is_required(false): iroh's own *default* IPv6 bind is allowed to
        // fail (plenty of hosts/containers don't have IPv6 at all), but
        // bind_addr_with_opts defaults is_required to true — without this
        // override, a container with no IPv6 would fail to start
        // entirely over a socket this code doesn't actually need.
        .bind_addr_with_opts(
            format!("[::]:{}", config.sync_port),
            iroh::endpoint::BindOpts::default().set_is_required(false),
        )
        .context("failed to configure IPv6 sync port")?
        // Purely additive: if a buddy isn't on the same LAN (the normal
        // case), mDNS finds nothing and we fall back to the
        // relay/direct-over-internet path exactly as before.
        .address_lookup(mdns.clone())
        .bind()
        .await
        .context("failed to bind Iroh endpoint")?;

    tracing::info!(node_id = %endpoint_id, "backup-buddies client starting");

    // Who's currently visible on the local network via mDNS — shared so the
    // dashboard can show a live count (Syncthing-style "discovery" signal),
    // not just something logged once at discovery time. Same set the
    // logging block below already tracked locally; now just behind a Mutex
    // so two consumers (this task and the dashboard's /api/status) can both
    // read it.
    let mdns_peers: Arc<Mutex<std::collections::HashSet<EndpointId>>> =
        Arc::new(Mutex::new(std::collections::HashSet::new()));

    // Log what mDNS actually sees, so this is visible/debuggable from the
    // container logs rather than a silent background mechanism — doesn't
    // affect connection behavior either way, iroh uses the address lookup
    // service's results on its own regardless of whether anyone's
    // listening on this stream.
    //
    // swarm-discovery re-announces/refreshes a peer's record periodically
    // (every second or so), which re-fires Discovered for the *same*
    // peer repeatedly — logging every one of those at INFO would drown
    // out everything else in the logs within seconds. Only the first
    // sighting of a given endpoint_id (or a re-sighting after it
    // expired) is worth a log line; track what's already been announced
    // and log the rest at DEBUG instead.
    {
        let mut events = mdns.subscribe().await;
        let mdns_peers = mdns_peers.clone();
        tokio::spawn(async move {
            use n0_future::StreamExt;
            while let Some(event) = events.next().await {
                match event {
                    DiscoveryEvent::Discovered { endpoint_info, .. } => {
                        let newly_seen = mdns_peers.lock().unwrap().insert(endpoint_info.endpoint_id);
                        if newly_seen {
                            tracing::info!(
                                endpoint_id = %endpoint_info.endpoint_id,
                                "found a buddy on the local network (mDNS) — direct LAN connection possible"
                            );
                        } else {
                            tracing::debug!(
                                endpoint_id = %endpoint_info.endpoint_id,
                                "mDNS re-announced a buddy already known on the local network"
                            );
                        }
                    }
                    DiscoveryEvent::Expired { endpoint_id } => {
                        mdns_peers.lock().unwrap().remove(&endpoint_id);
                        tracing::debug!(%endpoint_id, "mDNS-discovered buddy no longer visible on the local network");
                    }
                    // DiscoveryEvent is #[non_exhaustive] — future variants
                    // just get ignored here rather than breaking the build.
                    _ => {}
                }
            }
        });
    }

    // `restore <buddy node id> [restore_dir]` pulls everything that buddy
    // is holding for us and exits — a one-shot operation, not part of the
    // normal daemon loop below. e.g.:
    //   docker compose run --rm client restore <node-id>
    // (defaults to RESTORE_DIR/<node id>; pass a path to override)
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("restore") {
        let buddy_id: EndpointId = args
            .get(2)
            .context("usage: restore <buddy node id> [restore_dir]")?
            .parse()
            .context("not a valid Iroh node id")?;
        let restore_dir: PathBuf = args
            .get(3)
            .map(PathBuf::from)
            .unwrap_or_else(|| config.restore_dir.join(buddy_id.to_string()));
        tokio::fs::create_dir_all(&restore_dir).await?;

        tracing::info!(buddy = %buddy_id, dir = %restore_dir.display(), "starting restore");
        let stats = restore::run_restore(
            &endpoint,
            &config.relay_url,
            &config.passphrase,
            buddy_id,
            &restore_dir,
        )
        .await?;
        tracing::info!(
            count = stats.files_restored,
            bytes = stats.bytes_restored,
            duration_ms = stats.duration_ms,
            dir = %restore_dir.display(),
            "restore complete"
        );

        endpoint.close().await;
        return Ok(());
    }

    register_node_id(&http, &config, &endpoint_id).await?;

    // Seed the pledge book with what we've received from each buddy so
    // far (pledged_bytes is left at 0 for now — the poll loop below fills
    // it in on its first run, before accept_task can enforce anything
    // meaningfully; until then, incoming data is rejected, which is the
    // safe default for an unknown pledge).
    //
    // The saved ledger is a running total, so it's checked against what's
    // really on disk at every start and corrected if it drifted — otherwise
    // a buddy could be refused as "pledge full" with space to spare (seen
    // live: ISOs long gone still counted against a 5 GB pledge).
    let saved_usage = receive::load_usage_ledger(&config.data_dir).await;
    let disk_usage = receive::usage_from_disk(&config.buddy_files_dir).await;
    for (id, &saved) in &saved_usage {
        let actual = disk_usage.get(id).copied().unwrap_or(0);
        if saved != actual {
            tracing::info!(buddy = %id, saved_bytes = saved, actual_bytes = actual, "corrected pledge usage to match what's on disk");
        }
    }
    let pledge_book: PledgeBook = Arc::new(Mutex::new(
        disk_usage
            .into_iter()
            .map(|(id, received_bytes)| (id, PledgeState { received_bytes, ..Default::default() }))
            .collect(),
    ));
    if let Err(err) = receive::save_usage_ledger(&config.data_dir, &pledge_book).await {
        tracing::warn!(?err, "failed to save corrected usage ledger");
    }

    // Lifetime relay-vs-direct byte totals — see bandwidth.rs. Loaded once
    // at startup so a restart doesn't reset the counter back to zero.
    let bandwidth_book: bandwidth::BandwidthBook =
        Arc::new(Mutex::new(bandwidth::load(&config.data_dir).await));

    // What the outbound loop below did on its last pass per buddy — the
    // dashboard reads this directly rather than probing anything itself.
    let cycle_stats: dashboard::CycleBook = Arc::new(Mutex::new(std::collections::HashMap::new()));

    // Same idea, for reconciliation results (see
    // backup::reconcile_with_buddy) — a separate book since it updates on
    // its own, much less frequent cadence, not every ordinary cycle.
    let reconcile_stats: dashboard::ReconcileBook =
        Arc::new(Mutex::new(std::collections::HashMap::new()));

    // Live progress of any backup cycle running right now, per buddy — so a
    // long first backup shows files/bytes done on the dashboard instead of
    // "no cycle yet" until the whole thing finishes.
    let cycle_progress: backup::CycleProgressBook = Arc::new(Mutex::new(std::collections::HashMap::new()));

    // This device's own label, as set in the web dashboard's Devices card
    // — None until the outbound loop's first successful poll of
    // /devices/me/buddies fills it in (see fetch_buddy_devices). The local
    // dashboard shows this instead of the bare node id once it's known, so
    // "This Device" reads as something recognizable rather than a token.
    let self_label: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    // Newest client version the server advertises — see update_check.rs.
    // Checked in the background; the dashboard compares it to this build's
    // own version. UPDATE_CHECK_URL overrides where to look ("off" disables
    // the check entirely); by default it's derived from API_URL.
    let latest_version: update_check::LatestVersion = Arc::new(Mutex::new(None));
    let update_url = match std::env::var("UPDATE_CHECK_URL").ok().map(|s| s.trim().to_string()) {
        Some(s) if s.eq_ignore_ascii_case("off") => None,
        Some(s) if !s.is_empty() => Some(s),
        _ => update_check::default_check_url(&config.api_url),
    };
    if let Some(url) = update_url {
        tokio::spawn(update_check::run(http.clone(), url, latest_version.clone()));
    }

    let dashboard_task = {
        let endpoint = endpoint.clone();
        let node_id_str = endpoint_id.to_string();
        let config_dashboard_bind = config.dashboard_bind.clone();
        let data_dir = config.data_dir.clone();
        let buddy_files_dir = config.buddy_files_dir.clone();
        let restore_dir = config.restore_dir.clone();
        let restore_dir_display = config.restore_dir_display.clone();
        let backup_dir = config.backup_dir.clone();
        let pledge_book = pledge_book.clone();
        let bandwidth_book = bandwidth_book.clone();
        let cycle_stats = cycle_stats.clone();
        let reconcile_stats = reconcile_stats.clone();
        let cycle_progress = cycle_progress.clone();
        let self_label = self_label.clone();
        let mdns_peers = mdns_peers.clone();
        let latest_version = latest_version.clone();
        let relay_url = config.relay_url.clone();
        let passphrase = config.passphrase.clone();
        let stale_after_secs = config.stale_after_secs;
        tokio::spawn(async move {
            if let Err(err) = dashboard::run(
                &config_dashboard_bind,
                node_id_str,
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
                config.scan_interval_secs,
                endpoint,
                relay_url,
                passphrase,
                stale_after_secs,
            )
            .await
            {
                tracing::warn!(?err, "dashboard server stopped");
            }
        })
    };

    // Accept loop: our buddy's client may connect to *us* first. Runs for
    // the life of the process alongside the periodic outbound cycle below.
    let accept_task = {
        let endpoint = endpoint.clone();
        let data_dir = config.data_dir.clone();
        let buddy_files_dir = config.buddy_files_dir.clone();
        let pledge_book = pledge_book.clone();
        let bandwidth_book = bandwidth_book.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let data_dir = data_dir.clone();
                let buddy_files_dir = buddy_files_dir.clone();
                let pledge_book = pledge_book.clone();
                let bandwidth_book = bandwidth_book.clone();
                tokio::spawn(async move {
                    if let Err(err) = receive::handle_incoming(
                        incoming,
                        data_dir,
                        buddy_files_dir,
                        pledge_book,
                        bandwidth_book,
                    )
                    .await
                    {
                        tracing::warn!(?err, "incoming connection failed");
                    }
                });
            }
        })
    };

    // Periodic loop: ask the control plane who our paired buddies' devices
    // are, refresh their pledge, and — if BACKUP_DIR is set — push up
    // whatever's changed there since the last cycle. When there's nothing
    // to back up (no BACKUP_DIR configured), this still serves as the
    // connectivity check the old test-payload loop used to be, via Ping.
    let outbound_task = {
        let endpoint = endpoint.clone();
        let http = http.clone();
        let pledge_book = pledge_book.clone();
        let bandwidth_book = bandwidth_book.clone();
        let cycle_stats = cycle_stats.clone();
        let reconcile_stats = reconcile_stats.clone();
        let cycle_progress = cycle_progress.clone();
        let self_label = self_label.clone();
        async move {
            // When each buddy's manifest was last reconciled against what
            // they actually report holding for us (see
            // backup::reconcile_with_buddy) — separate from the ordinary
            // ~30s cycle above, and deliberately much less frequent, since
            // it costs the buddy a full file listing rather than only
            // touching the network when something local changed. Declared
            // here, outside the loop below, so it persists across ticks
            // for the life of this process.
            let mut last_reconcile: std::collections::HashMap<String, std::time::Instant> =
                std::collections::HashMap::new();
            const RECONCILE_INTERVAL: Duration = Duration::from_secs(600); // 10 minutes

            // Don't dial anyone until the relay connection is up (~3s
            // after start). A connection opened before then has the direct
            // LAN path as its only path; seen live, iroh then closes that
            // path once the relay arrives ("failed closing path
            // err=LastOpenPath") and the connection hangs ~45s and times
            // out, failing the rest of the first cycle after every restart.
            // Bounded, so a device that can't reach the relay (LAN-only)
            // still starts backing up, just as before.
            if tokio::time::timeout(Duration::from_secs(15), endpoint.online()).await.is_err() {
                tracing::warn!("relay still not connected after 15s — starting backups anyway (direct connections only until it is)");
            }

            loop {
                match fetch_buddy_devices(&http, &config, &bandwidth_book).await {
                    Ok((true, _buddies, label)) => {
                        // Still record the label even while paused — it's
                        // this device's own identity, unrelated to whether
                        // buddy syncing is currently allowed.
                        *self_label.lock().unwrap() = label;
                        // Account is paused (relay_status != 'active' —
                        // see stripe-webhook.js) — per product decision,
                        // this stops ALL buddy syncing, not just relay
                        // traffic, so nothing here opens a connection,
                        // sends a file, pings, or reconciles until the
                        // account is active again. The dashboard banner
                        // (dashboard.html) and the payment-failed email
                        // are what the account holder actually sees; this
                        // is just honoring that pause on the wire.
                        tracing::warn!(
                            "this account's relay syncing is paused (billing issue) — \
                             skipping all buddy activity this cycle"
                        );
                    }
                    Ok((false, buddies, label)) => {
                        *self_label.lock().unwrap() = label;
                        for buddy in buddies {
                            let Some(node_id_str) = &buddy.iroh_node_id else {
                                tracing::info!(
                                    account_id = %buddy.account_id,
                                    "buddy hasn't registered a device yet — skipping"
                                );
                                continue;
                            };
                            let Ok(buddy_id) = node_id_str.parse::<EndpointId>() else {
                                tracing::warn!(node_id = %node_id_str, "buddy sent an unparseable node id");
                                continue;
                            };

                            // Refresh what this buddy has pledged us, every
                            // cycle — a re-created pairing can change it,
                            // and this is also how a brand-new buddy first
                            // gets enforcement enabled for incoming data
                            // (see receive.rs's "unknown buddy" handling).
                            let pledged_bytes = buddy
                                .pledged_bytes
                                .as_deref()
                                .and_then(|s| s.parse::<u64>().ok())
                                .unwrap_or(0);
                            {
                                let mut book = pledge_book.lock().unwrap();
                                book.entry(node_id_str.clone()).or_default().pledged_bytes = pledged_bytes;
                            }

                            let label = buddy.label.clone().unwrap_or_else(|| buddy.account_id.clone());

                            if let Some(backup_dir) = &config.backup_dir {
                                let result = backup::run_backup_cycle(
                                    &endpoint,
                                    &config.relay_url,
                                    backup_dir,
                                    buddy_id,
                                    Some(&cycle_progress),
                                )
                                .await;
                                if let Ok(stats) = &result
                                    && let Some(traffic) = stats.traffic
                                {
                                    bandwidth::record_split(&config.data_dir, &bandwidth_book, traffic).await;
                                }
                                let record = match &result {
                                    Ok(stats)
                                        if stats.files_sent == 0
                                            && stats.files_deleted == 0
                                            && stats.files_failed == 0 =>
                                    {
                                        // Truly idle: run_backup_cycle found nothing new to
                                        // send and, per its own doc comment, never opened a
                                        // connection at all — so unlike the general "nothing
                                        // sent" case below, reachability here has not actually
                                        // been checked by anything yet. Piggyback the same
                                        // lightweight Ping the no-BACKUP_DIR branch below already
                                        // uses as its own connectivity check, so a dead buddy
                                        // doesn't sit at "backup ok" forever just because there
                                        // was nothing to resend.
                                        let ping_result =
                                            ping(&endpoint, &config.relay_url, buddy_id).await;
                                        dashboard::CycleRecord {
                                            label: label.clone(),
                                            at: dashboard::unix_now(),
                                            kind: "backup",
                                            ok: ping_result.is_ok(),
                                            detail: match &ping_result {
                                                Ok(()) => {
                                                    "nothing new to back up (connectivity check ok)"
                                                        .to_string()
                                                }
                                                Err(err) => format!(
                                                    "nothing new to back up, but connectivity \
                                                     check failed: {err}"
                                                ),
                                            },
                                            files_sent: Some(0),
                                            files_deleted: Some(0),
                                            bytes_sent: None,
                                            duration_ms: None,
                                            connection: None,
                                            files_failed: Some(0),
                                            failed_files: Vec::new(),
                                            last_ok_at: None,
                                            consecutive_failures: 0,
                                            // This is now backed by a real Ping instead of an
                                            // unconditional assumption — the actual reachability
                                            // signal "stale" is meant to track.
                                            made_progress: ping_result.is_ok(),
                                            last_synced_at: None,
                                        }
                                    }
                                    Ok(stats) if stats.files_sent == 0 && stats.files_deleted == 0 => {
                                        dashboard::CycleRecord {
                                            label: label.clone(),
                                            at: dashboard::unix_now(),
                                            kind: "backup",
                                            ok: false,
                                            detail: format!(
                                                "{} file(s) still failing to sync",
                                                stats.files_failed
                                            ),
                                            files_sent: Some(0),
                                            files_deleted: Some(0),
                                            bytes_sent: None,
                                            duration_ms: None,
                                            connection: None,
                                            files_failed: Some(stats.files_failed),
                                            failed_files: stats
                                                .failed_paths
                                                .iter()
                                                .cloned()
                                                .map(dashboard::FailedFileView::from)
                                                .collect(),
                                            last_ok_at: None,
                                            consecutive_failures: 0,
                                            // files_failed > 0 here means run_backup_cycle *did*
                                            // open a connection and attempt to send (e.g. pledge
                                            // enforcement rejected it) — reachability is already
                                            // proven for this cycle, no extra ping needed. A
                                            // permanently-stuck file (over pledge, too large,
                                            // etc.) fails every single cycle forever by
                                            // definition, so gating progress on files_failed == 0
                                            // would make a perfectly healthy connection look
                                            // "stale — last synced never" permanently. That
                                            // specific-file problem is already called out loudly
                                            // by the failed-files line and the "backup failed"
                                            // pill right next to it — staleness doesn't need to
                                            // repeat it.
                                            made_progress: true,
                                            last_synced_at: None,
                                        }
                                    }
                                    Ok(stats) => dashboard::CycleRecord {
                                        label: label.clone(),
                                        at: dashboard::unix_now(),
                                        kind: "backup",
                                        ok: stats.files_failed == 0,
                                        detail: "backup cycle complete".to_string(),
                                        files_sent: Some(stats.files_sent),
                                        files_deleted: Some(stats.files_deleted),
                                        bytes_sent: Some(stats.bytes_sent),
                                        duration_ms: Some(stats.duration_ms),
                                        connection: stats.connection,
                                        files_failed: Some(stats.files_failed),
                                        failed_files: stats
                                            .failed_paths
                                            .iter()
                                            .cloned()
                                            .map(dashboard::FailedFileView::from)
                                            .collect(),
                                        last_ok_at: None,
                                        consecutive_failures: 0,
                                        // At least one file actually moved this cycle,
                                        // regardless of whether others are still stuck.
                                        made_progress: true,
                                        last_synced_at: None,
                                    },
                                    Err(err) => dashboard::CycleRecord {
                                        label: label.clone(),
                                        at: dashboard::unix_now(),
                                        kind: "backup",
                                        ok: false,
                                        detail: err.to_string(),
                                        files_sent: None,
                                        files_deleted: None,
                                        bytes_sent: None,
                                        duration_ms: None,
                                        connection: None,
                                        files_failed: None,
                                        failed_files: Vec::new(),
                                        last_ok_at: None,
                                        consecutive_failures: 0,
                                        made_progress: false,
                                        last_synced_at: None,
                                    },
                                };
                                // Log against `record` (not `result` directly) so the idle
                                // case's log reflects the ping we just ran instead of
                                // re-deriving a verdict without it.
                                match &result {
                                    Ok(stats) if stats.files_sent == 0 && stats.files_deleted == 0 => {
                                        if record.ok {
                                            tracing::debug!(
                                                buddy = %label,
                                                "nothing new to back up (connectivity check ok)"
                                            )
                                        } else if stats.files_failed == 0 {
                                            tracing::warn!(
                                                buddy = %label,
                                                detail = %record.detail,
                                                "nothing new to back up, and connectivity check failed"
                                            )
                                        } else {
                                            tracing::warn!(
                                                buddy = %label,
                                                files_failed = stats.files_failed,
                                                "backup cycle complete with file(s) still failing to sync"
                                            )
                                        }
                                    }
                                    Ok(stats) => tracing::info!(
                                        buddy = %label,
                                        files_sent = stats.files_sent,
                                        files_deleted = stats.files_deleted,
                                        bytes_sent = stats.bytes_sent,
                                        duration_ms = stats.duration_ms,
                                        "backup cycle complete"
                                    ),
                                    Err(err) => tracing::warn!(buddy = %label, ?err, "backup cycle failed"),
                                }
                                dashboard::record_cycle(&cycle_stats, node_id_str, record);

                                // Periodic reconciliation — independent of
                                // whether this particular cycle had anything
                                // to send, since the whole point is to catch
                                // drift that never shows up as a local file
                                // change in the first place (see
                                // backup::reconcile_with_buddy's doc comment).
                                let reconcile_due = last_reconcile
                                    .get(node_id_str)
                                    .map(|at: &std::time::Instant| at.elapsed() >= RECONCILE_INTERVAL)
                                    .unwrap_or(true);
                                if reconcile_due {
                                    last_reconcile
                                        .insert(node_id_str.clone(), std::time::Instant::now());
                                    let reconcile_result = backup::reconcile_with_buddy(
                                        &endpoint,
                                        &config.relay_url,
                                        buddy_id,
                                    )
                                    .await;
                                    let record = match &reconcile_result {
                                        Ok(stats) => dashboard::ReconcileRecord {
                                            at: dashboard::unix_now(),
                                            checked: stats.checked,
                                            missing_on_buddy: stats.missing_on_buddy.clone(),
                                            unexpected_on_buddy: stats.unexpected_on_buddy.clone(),
                                            error: None,
                                        },
                                        Err(err) => dashboard::ReconcileRecord {
                                            at: dashboard::unix_now(),
                                            checked: 0,
                                            missing_on_buddy: Vec::new(),
                                            unexpected_on_buddy: Vec::new(),
                                            error: Some(err.to_string()),
                                        },
                                    };
                                    reconcile_stats.lock().unwrap().insert(node_id_str.clone(), record);
                                    match reconcile_result {
                                        Ok(stats)
                                            if stats.missing_on_buddy.is_empty()
                                                && stats.unexpected_on_buddy.is_empty() =>
                                        {
                                            tracing::debug!(
                                                buddy = %label,
                                                checked = stats.checked,
                                                "reconciliation: buddy's stored files match our manifest"
                                            );
                                        }
                                        Ok(stats) => tracing::warn!(
                                            buddy = %label,
                                            checked = stats.checked,
                                            missing_on_buddy = stats.missing_on_buddy.len(),
                                            missing_paths = ?stats.missing_on_buddy,
                                            unexpected_on_buddy = stats.unexpected_on_buddy.len(),
                                            unexpected_paths = ?stats.unexpected_on_buddy,
                                            "reconciliation found drift between our manifest and \
                                             the buddy's actual files — missing ones will be \
                                             re-sent automatically next cycle"
                                        ),
                                        Err(err) => tracing::warn!(
                                            buddy = %label, ?err,
                                            "reconciliation check against buddy's actual files failed"
                                        ),
                                    }
                                }
                            } else {
                                let result = ping(&endpoint, &config.relay_url, buddy_id).await;
                                let record = dashboard::CycleRecord {
                                    label: label.clone(),
                                    at: dashboard::unix_now(),
                                    kind: "ping",
                                    ok: result.is_ok(),
                                    detail: match &result {
                                        Ok(()) => "connectivity check succeeded".to_string(),
                                        Err(err) => err.to_string(),
                                    },
                                    files_sent: None,
                                    files_deleted: None,
                                    bytes_sent: None,
                                    duration_ms: None,
                                    connection: None,
                                    files_failed: None,
                                    failed_files: Vec::new(),
                                    last_ok_at: None,
                                    consecutive_failures: 0,
                                    made_progress: result.is_ok(),
                                    last_synced_at: None,
                                };
                                dashboard::record_cycle(&cycle_stats, node_id_str, record);
                                match result {
                                    Ok(()) => tracing::info!(buddy = %label, "connectivity check succeeded"),
                                    Err(err) => {
                                        tracing::warn!(buddy = %label, ?err, "connectivity check failed")
                                    }
                                }
                            }
                        }
                    }
                    Err(err) => tracing::warn!(?err, "could not fetch buddy devices from API"),
                }

                tokio::time::sleep(Duration::from_secs(config.scan_interval_secs)).await;
            }
        }
    };

    tokio::select! {
        _ = accept_task => {}
        _ = outbound_task => {}
        _ = dashboard_task => {}
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
        }
    }

    endpoint.close().await;
    Ok(())
}

async fn load_or_generate_secret_key(data_dir: &Path) -> Result<SecretKey> {
    let key_path = data_dir.join("iroh_secret_key");
    if let Ok(bytes) = tokio::fs::read(&key_path).await {
        let array: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .context("stored iroh_secret_key file is the wrong size")?;
        return Ok(SecretKey::from_bytes(&array));
    }

    let key = SecretKey::generate();
    tokio::fs::write(&key_path, key.to_bytes()).await?;
    tracing::info!("generated a new, persistent Iroh identity for this device");
    Ok(key)
}

#[derive(Deserialize)]
struct DeviceSelf {
    account_id: String,
}

// Which account this device belongs to, from the API (devices.js's GET
// /devices/me). Saved in DATA_DIR, so a device that starts while the API is
// unreachable still derives the right encryption key.
async fn load_account_id(http: &reqwest::Client, config: &Config) -> Result<String> {
    let saved_path = config.data_dir.join("account-id");
    let saved = tokio::fs::read_to_string(&saved_path)
        .await
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let fetched = async {
        let resp: DeviceSelf = http
            .get(format!("{}/devices/me", config.api_url))
            .bearer_auth(&config.device_token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        anyhow::Ok(resp.account_id)
    }
    .await;

    match (fetched, saved) {
        (Ok(id), saved) => {
            if saved.as_deref() != Some(id.as_str()) {
                if let Some(old) = &saved {
                    tracing::warn!(
                        old_account = %old,
                        new_account = %id,
                        "this device's token now belongs to a different account; files it sends from now on are encrypted with that account's key"
                    );
                }
                tokio::fs::write(&saved_path, &id).await.context("failed to save the account id in DATA_DIR")?;
            }
            Ok(id)
        }
        (Err(err), Some(id)) => {
            tracing::warn!(error = %err, "couldn't reach the API to confirm this device's account; using the saved one");
            Ok(id)
        }
        (Err(err), None) => Err(err.context(
            "failed to look up this device's account from the API (needed once, to derive the encryption key) — check API_URL and DEVICE_TOKEN",
        )),
    }
}

async fn register_node_id(http: &reqwest::Client, config: &Config, endpoint_id: &EndpointId) -> Result<()> {
    http.put(format!("{}/devices/me/node-id", config.api_url))
        .bearer_auth(&config.device_token)
        .json(&serde_json::json!({ "iroh_node_id": endpoint_id.to_string() }))
        .send()
        .await
        .context("failed to reach the API to register this device's node id")?
        .error_for_status()
        .context("API rejected device registration — check DEVICE_TOKEN")?;

    tracing::info!("registered this device's node id with the API");
    Ok(())
}

// Returns (paused, buddy_devices, self_label) — see BuddiesResponse's
// fields.
async fn fetch_buddy_devices(
    http: &reqwest::Client,
    config: &Config,
    bandwidth_book: &bandwidth::BandwidthBook,
) -> Result<(bool, Vec<BuddyDevice>, Option<String>)> {
    // Piggyback relay-bandwidth reporting on this existing poll (see
    // apps/api/src/routes/devices.js) rather than a separate endpoint —
    // whole megabytes of relay traffic accumulated since the last
    // successful report. Only advance the high-water mark (below) once the
    // request actually succeeds, so a failed poll just re-reports the same
    // bytes next cycle instead of losing them.
    let relay_mb = bandwidth::pending_relay_mb(bandwidth_book);

    let resp = http
        .get(format!(
            "{}/devices/me/buddies?relay_mb={}",
            config.api_url, relay_mb
        ))
        .bearer_auth(&config.device_token)
        .send()
        .await?
        .error_for_status()?;

    if relay_mb > 0 {
        bandwidth::mark_relay_reported(&config.data_dir, bandwidth_book, relay_mb).await;
    }

    let resp: BuddiesResponse = resp.json().await?;
    Ok((resp.paused, resp.buddy_devices, resp.self_label))
}

// Connectivity check for a buddy we're not backing anything up to (no
// BACKUP_DIR configured) — proves registration, discovery, NAT traversal
// via our relay, and the Iroh connection all still work, the same thing
// the old dedicated test-payload protocol proved, now just one variant of
// the real sync protocol instead of a second one running alongside it.
async fn ping(endpoint: &Endpoint, relay_url: &RelayUrl, buddy_id: EndpointId) -> Result<()> {
    let addr = EndpointAddr::new(buddy_id).with_relay_url(relay_url.clone());
    let conn = endpoint.connect(addr, protocol::ALPN).await.map_err(protocol::explain_connect_error)?;

    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;
    protocol::write_frame(&mut send, &protocol::SyncRequest::Ping).await?;
    send.finish().context("failed to finish send stream")?;

    let ack: protocol::SyncAck =
        protocol::read_frame(&mut recv).await.context("failed to read ack from buddy")?;
    if !ack.ok {
        anyhow::bail!("buddy rejected ping: {}", ack.error.unwrap_or_default());
    }
    Ok(())
}
