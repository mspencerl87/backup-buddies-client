// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

//! End-to-end tests of the transfer code: two real iroh endpoints on
//! localhost, the real backup / receive / restore paths, no mocks in
//! between. Only the control-plane API (which would normally tell each side
//! who its buddy is) is skipped — the tests wire the two endpoints to each
//! other directly.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use iroh::address_lookup::memory::MemoryLookup;
use iroh::{endpoint::presets::Minimal, Endpoint, RelayMode, RelayUrl, SecretKey};
use secrecy::SecretString;

use crate::protocol;
use crate::receive::{PledgeBook, PledgeState};

const PASS: &str = crate::crypto::tests::TEST_PASSPHRASE;

async fn endpoint(alpns: Vec<Vec<u8>>, lookup: MemoryLookup) -> Endpoint {
    Endpoint::builder(Minimal)
        .secret_key(SecretKey::generate())
        .alpns(alpns)
        .relay_mode(RelayMode::Disabled)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .address_lookup(lookup)
        .bind()
        .await
        .unwrap()
}

/// A receiving "buddy": accepts connections and serves them with the real
/// receive code, storing under `buddy_files`.
fn serve(ep: Endpoint, data_dir: PathBuf, buddy_files: PathBuf, pledge: PledgeBook) {
    let bandwidth = Arc::new(Mutex::new(crate::bandwidth::BandwidthTotals::default()));
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let (d, b, p, bw) = (data_dir.clone(), buddy_files.clone(), pledge.clone(), bandwidth.clone());
            tokio::spawn(async move {
                if let Err(err) = crate::receive::handle_incoming(incoming, d, b, p, bw).await {
                    eprintln!("receiver: {err:?}");
                }
            });
        }
    });
}

fn write(dir: &Path, rel: &str, data: &[u8]) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, data).unwrap();
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

/// Protocol v5: the buddy stores a backup's repository files, by kind and
/// id, checks each against its name, and counts them against the pledge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_repo_files() {
    use crate::protocol::RepoFileKind::{Config, Index, Pack};
    use sha2::{Digest, Sha256};

    let root = std::env::temp_dir().join(format!("bb-e2e-repo-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (config_b, buddy_files_b) = (root.join("b/config"), root.join("b/buddy-files"));
    for d in [&config_b, &buddy_files_b] {
        std::fs::create_dir_all(d).unwrap();
    }
    let lookup_a = MemoryLookup::new();
    let ep_b = endpoint(vec![protocol::ALPN.to_vec()], MemoryLookup::new()).await;
    let ep_a = endpoint(vec![protocol::ALPN.to_vec()], lookup_a.clone()).await;
    lookup_a.add_endpoint_info(ep_b.addr());
    let a_id = ep_a.id().to_string();
    let pledge: PledgeBook = Arc::new(Mutex::new(HashMap::from([(
        a_id.clone(),
        PledgeState { pledged_bytes: 3_000_000, received_bytes: 0, account_id: None },
    )])));
    serve(ep_b.clone(), config_b.clone(), buddy_files_b.clone(), pledge.clone());
    let conn = ep_a.connect(ep_b.addr(), protocol::ALPN).await.unwrap();
    let id_of = |data: &[u8]| hex::encode(Sha256::digest(data));
    let used = || pledge.lock().unwrap()[&a_id].received_bytes;

    // Writes, lists and reads back, in part and whole.
    let pack = pattern(1_000_000, 3);
    let pack_id = id_of(&pack);
    crate::repo::write(&conn, Pack, &pack_id, &pack).await.unwrap();
    crate::repo::write(&conn, Config, crate::repo::CONFIG_ID, b"config bytes").await.unwrap();
    let listed = crate::repo::list(&conn, Pack).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!((listed[0].id.as_str(), listed[0].size), (pack_id.as_str(), 1_000_000));
    assert_eq!(crate::repo::list(&conn, Config).await.unwrap()[0].id, crate::repo::CONFIG_ID);
    assert!(crate::repo::list(&conn, Index).await.unwrap().is_empty());
    assert_eq!(crate::repo::read(&conn, Pack, &pack_id, 0, None).await.unwrap(), pack);
    assert_eq!(crate::repo::read(&conn, Pack, &pack_id, 999_990, Some(10)).await.unwrap(), &pack[999_990..]);
    assert!(crate::repo::read(&conn, Pack, &pack_id, 999_995, Some(10)).await.is_err(), "past the end");
    assert_eq!(used(), 1_000_000 + 12);

    // Bytes that don't match their name are refused and not kept.
    let other = pattern(1000, 9);
    assert!(crate::repo::write(&conn, Index, &id_of(b"something else"), &other).await.is_err());
    assert!(crate::repo::list(&conn, Index).await.unwrap().is_empty());
    assert_eq!(used(), 1_000_000 + 12, "a refused write gives its reservation back");

    // A write past the pledge is refused before its bytes are read, with
    // the reason as its STOP_SENDING code.
    let big = pattern(2_500_000, 5);
    let err = crate::repo::write(&conn, Pack, &id_of(&big), &big).await.unwrap_err();
    let refused = err.chain().any(|c| {
        matches!(c.downcast_ref::<iroh::endpoint::WriteError>(),
            Some(iroh::endpoint::WriteError::Stopped(code)) if protocol::PutRejectReason::from_code(code.into_inner()) == Some(protocol::PutRejectReason::PledgeExceeded))
    }) || err.to_string().contains("pledge");
    assert!(refused, "expected a pledge refusal, got {err:?}");

    // Stored under the sender's .repo/, counted in usage from disk.
    let sender_dir = buddy_files_b.join(&a_id);
    assert!(crate::repo::repo_dir(&sender_dir).join("data").join(&pack_id[..2]).join(&pack_id).is_file());
    assert_eq!(crate::receive::usage_from_disk(&buddy_files_b).await[&a_id], 1_000_000 + 12);

    // Removing frees the pledge, and removing again is fine.
    crate::repo::remove(&conn, Pack, &pack_id).await.unwrap();
    crate::repo::remove(&conn, Pack, &pack_id).await.unwrap();
    assert!(crate::repo::list(&conn, Pack).await.unwrap().is_empty());
    assert_eq!(used(), 12);
    assert!(crate::repo::read(&conn, Pack, &pack_id, 0, None).await.is_err());

    conn.close(0u32.into(), b"done");
    let _ = std::fs::remove_dir_all(&root);
}

/// Backups end to end against a real buddy: a snapshot of the backup
/// folder lands in the buddy's repository; renames and moves send next to
/// nothing; a 1-byte edit in a big file sends about one chunk; the data
/// reads back through rustic with the passphrase-derived key; Browse
/// files, History and restores work; and a full pledge refuses the write.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_chunked_backup() {
    let root = std::env::temp_dir().join(format!("bb-e2e-chunked-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (mine, config_a) = (root.join("a/my-files"), root.join("a/config"));
    let (config_b, buddy_files_b) = (root.join("b/config"), root.join("b/buddy-files"));
    for d in [&mine, &config_a, &config_b, &buddy_files_b] {
        std::fs::create_dir_all(d).unwrap();
    }
    crate::crypto::init(&SecretString::from(PASS.to_string()), crate::crypto::tests::TEST_ACCOUNT).unwrap();
    crate::chunked::init(&config_a);
    let relay: RelayUrl = "https://relay.invalid".parse().unwrap();
    let lookup_a = MemoryLookup::new();
    let ep_b = endpoint(vec![protocol::ALPN.to_vec()], MemoryLookup::new()).await;
    let ep_a = endpoint(vec![protocol::ALPN.to_vec()], lookup_a.clone()).await;
    lookup_a.add_endpoint_info(ep_b.addr());
    let (a_id, b_id) = (ep_a.id().to_string(), ep_b.id());
    let pledge: PledgeBook = Arc::new(Mutex::new(HashMap::from([(
        a_id.clone(),
        PledgeState { pledged_bytes: 1 << 40, received_bytes: 0, account_id: None },
    )])));
    serve(ep_b.clone(), config_b.clone(), buddy_files_b.clone(), pledge.clone());

    // Incompressible content, so sizes are meaningful.
    let noise = |n: usize, seed: u64| -> Vec<u8> {
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    };
    let big = noise(32_000_000, 1);
    write(&mine, "videos/clip.bin", &big);
    for i in 0..20 {
        write(&mine, &format!("photos/2024/img{i:02}.jpg"), &noise(50_000, 100 + i));
    }
    let cycle = || crate::chunked::run_backup_cycle(&ep_a, &relay, &mine, b_id, None);
    let sender_dir = buddy_files_b.join(&a_id);

    // Nothing to browse or restore before the first backup.
    assert!(crate::chunked_restore::list(&ep_a, &relay, b_id).await.unwrap().files.is_empty());

    // 1. First backup: everything goes, into the repository. With a
    // progress book, the entry exists while the cycle runs and is gone
    // afterwards, so the dashboard never shows a stuck progress bar.
    let progress_book: crate::backup::CycleProgressBook = Arc::new(Mutex::new(HashMap::new()));
    let s = crate::chunked::run_backup_cycle(&ep_a, &relay, &mine, b_id, Some(&progress_book)).await.unwrap();
    assert!(progress_book.lock().unwrap().is_empty(), "progress entry left behind after the cycle");
    assert_eq!(s.files_sent, 21);
    assert!(s.bytes_sent > 32_500_000, "sent {}", s.bytes_sent);
    assert!(crate::repo::repo_size(&sender_dir).await > 32_500_000);
    // Relay is off in this test, so every byte is booked as direct.
    let traffic = s.traffic.expect("traffic measured");
    assert_eq!(traffic.relay, 0, "{traffic:?}");
    assert!(traffic.direct >= s.bytes_sent, "{traffic:?} vs {}", s.bytes_sent);
    assert_eq!(crate::chunked::last_snapshot_summary(&b_id.to_string()).map(|(files, _)| files), Some(21));

    // 2. Nothing changed, but retention is due right after the first
    // snapshot: it runs (prune finds nothing), sending no files.
    let s = cycle().await.unwrap();
    assert_eq!((s.files_sent, s.files_deleted), (0, 0));
    assert!(s.traffic.is_some(), "connected for retention");
    // 3. Still nothing changed and retention is done: idle, but it still
    // checks the buddy has the backup.
    let s = cycle().await.unwrap();
    assert_eq!((s.files_sent, s.files_deleted, s.bytes_sent), (0, 0, 0));
    assert!(s.connection.is_some(), "an idle cycle checks with the buddy");

    // 4. Rename the big file and move the photos: next to nothing is sent.
    std::fs::rename(mine.join("videos/clip.bin"), mine.join("videos/renamed.bin")).unwrap();
    std::fs::rename(mine.join("photos/2024"), mine.join("photos/holiday")).unwrap();
    let s = cycle().await.unwrap();
    assert_eq!((s.files_sent, s.files_deleted), (21, 21), "21 new paths, 21 gone");
    assert!(s.bytes_sent < 200_000, "a rename sent {} bytes", s.bytes_sent);
    eprintln!("chunked: renaming 32 MB + moving 20 photos sent {} bytes", s.bytes_sent);
    // Activity lists the paths, from comparing the snapshot with its parent.
    assert!(s.sent_paths.contains(&"videos/renamed.bin".to_string()), "{:?}", s.sent_paths);
    assert!(s.sent_paths.contains(&"photos/holiday/img07.jpg".to_string()));
    assert!(s.deleted_paths.contains(&"videos/clip.bin".to_string()), "{:?}", s.deleted_paths);
    assert_eq!((s.sent_paths.len(), s.deleted_paths.len()), (21, 21));

    // 5. One byte changed in the middle of 32 MB: one chunk, which is
    // 0.5–8 MB depending on where this repository's chunker (it picks its
    // own random polynomial) happens to cut.
    let mut edited = big.clone();
    edited[16_000_000] ^= 0xff;
    write(&mine, "videos/renamed.bin", &edited);
    let s = cycle().await.unwrap();
    assert_eq!(s.files_sent, 1);
    assert!(s.bytes_sent < 9_000_000, "a 1-byte edit sent {} bytes", s.bytes_sent);
    eprintln!("chunked: a 1-byte edit in 32 MB sent {} bytes", s.bytes_sent);
    assert_eq!(s.sent_paths, ["videos/renamed.bin"]);
    assert!(s.deleted_paths.is_empty());

    // The latest snapshot reads back through rustic, over the wire, with
    // the key derived from the passphrase.
    let backend = Arc::new(crate::repo_backend::BuddyBackend::new(ep_a.clone(), relay.clone(), b_id, None));
    let target = mine.join("videos/renamed.bin");
    let restored = tokio::task::spawn_blocking(move || {
        use rustic_core::{Credentials, LsOptions, Repository, RepositoryBackends, RepositoryOptions};
        let backends = RepositoryBackends::new(backend, None);
        let key: rustic_core::repofile::MasterKey = serde_json::from_value({
            use base64::Engine as _;
            let k = crate::crypto::repo_key();
            let b = |s: &[u8]| base64::engine::general_purpose::STANDARD.encode(s);
            serde_json::json!({"encrypt": b(&k[..32]), "mac": {"k": b(&k[32..48]), "r": b(&k[48..])}})
        })
        .unwrap();
        let repo = Repository::new(&RepositoryOptions::default().no_cache(true), &backends)
            .unwrap()
            .open(&Credentials::Masterkey(key))
            .unwrap()
            .to_indexed()
            .unwrap();
        let node = repo.node_from_snapshot_path("latest", |_| true).unwrap();
        let (_, file) = repo
            .ls(&node, &LsOptions::default())
            .unwrap()
            .map(Result::unwrap)
            .find(|(path, _)| Path::new("/").join(path) == target)
            .expect("the edited file is in the latest snapshot");
        let open = repo.open_file(&file).unwrap();
        repo.read_file_at(&open, 0, file.meta.size as usize).unwrap()
    })
    .await
    .unwrap();
    assert!(restored.as_ref() == edited.as_slice(), "restored bytes match the edited file");

    // Phase 3: the same backup through Browse files, History and restores.
    std::fs::remove_file(mine.join("photos/holiday/img00.jpg")).unwrap();
    let s = cycle().await.unwrap();
    assert_eq!((s.files_sent, s.files_deleted), (0, 1));
    let listing = crate::chunked_restore::list(&ep_a, &relay, b_id).await.unwrap();
    let live: Vec<_> = listing.files.iter().filter(|f| !f.deleted).map(|f| f.path.as_str()).collect();
    let gone: Vec<_> = listing.files.iter().filter(|f| f.deleted).map(|f| f.path.as_str()).collect();
    assert_eq!(live.len(), 20, "19 photos and the video: {live:?}");
    assert!(live.contains(&"videos/renamed.bin") && live.contains(&"photos/holiday/img05.jpg"));
    // Earlier paths that no longer exist show as deleted, still restorable.
    for path in ["photos/holiday/img00.jpg", "videos/clip.bin", "photos/2024/img05.jpg"] {
        assert!(gone.contains(&path), "{path} not listed as deleted: {gone:?}");
    }
    assert!(!listing.packs.is_empty() && listing.packs.iter().all(|p| crate::chunked_restore::pack_id(&p.remote).is_some()));

    // Restore everything live, through the dashboard's entry point.
    let restored_dir = root.join("a/restored");
    let stats = crate::chunked_restore::restore_files(&ep_a, &relay, b_id, &restored_dir, &listing.files, None)
        .await
        .unwrap();
    assert_eq!(stats.files_restored, 20);
    assert_eq!(std::fs::read(restored_dir.join("videos/renamed.bin")).unwrap(), edited);
    assert_eq!(
        std::fs::read(restored_dir.join("photos/holiday/img05.jpg")).unwrap(),
        std::fs::read(mine.join("photos/holiday/img05.jpg")).unwrap()
    );
    assert!(!restored_dir.join("photos/holiday/img00.jpg").exists(), "deleted files aren't restored with the rest");

    // History: the edited file has one earlier content (before the edit);
    // the deleted photo has its last one. Each restores next to the file.
    let versions = crate::chunked_restore::list_versions(&ep_a, &relay, b_id, "videos/renamed.bin").await.unwrap();
    assert_eq!(versions.len(), 1, "{versions:?}");
    crate::chunked_restore::restore_version(&ep_a, &relay, b_id, &restored_dir, "videos/renamed.bin", 1).await.unwrap();
    assert_eq!(std::fs::read(restored_dir.join("videos/renamed.bin.v1.bak")).unwrap(), big);
    let versions =
        crate::chunked_restore::list_versions(&ep_a, &relay, b_id, "photos/holiday/img00.jpg").await.unwrap();
    assert_eq!(versions.len(), 1);
    crate::chunked_restore::restore_version(&ep_a, &relay, b_id, &restored_dir, "photos/holiday/img00.jpg", 1)
        .await
        .unwrap();
    assert_eq!(std::fs::read(restored_dir.join("photos/holiday/img00.jpg.v1.bak")).unwrap(), noise(50_000, 100));

    // "What your buddy sees": a pack's first bytes, as stored (encrypted).
    let first = &listing.packs[0];
    let id = crate::chunked_restore::pack_id(&first.remote).unwrap();
    let peek = crate::chunked_restore::peek_pack(&ep_a, &relay, b_id, id, 256).await.unwrap();
    assert_eq!(peek.len() as u64, first.size.min(256));

    // A buddy that loses the backup (its folder deleted by hand) gets it
    // again in full on the next cycle, though nothing changed here.
    std::fs::remove_dir_all(&sender_dir).unwrap();
    let s = cycle().await.unwrap();
    assert_eq!((s.files_sent, s.files_deleted), (20, 0), "{s:?}");
    assert!(crate::repo::repo_size(&sender_dir).await > 32_500_000);
    assert_eq!(crate::chunked_restore::list(&ep_a, &relay, b_id).await.unwrap().files.len(), 20);
    let s = cycle().await.unwrap();
    assert_eq!(s.files_sent, 0, "and then it's idle again");

    // 6. A buddy whose pledge is full refuses the next pack, and the cycle
    // says so (the dashboard's DONT_FIT_REASONS matches those words).
    pledge.lock().unwrap().get_mut(&a_id).unwrap().pledged_bytes = 1;
    write(&mine, "new.bin", &noise(2_000_000, 7));
    let err = cycle().await.unwrap_err();
    assert!(err.to_string().contains("pledge"), "got: {err:#}");

    let _ = std::fs::remove_dir_all(&root);
}
