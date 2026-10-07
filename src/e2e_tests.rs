// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

//! End-to-end test of the transfer code: two real iroh endpoints on
//! localhost, the real send / receive / reconcile / restore paths, no
//! mocks in between. Only the control-plane API (which would normally tell
//! each side who its buddy is) is skipped — the test wires the two
//! endpoints to each other directly.
//!
//! `BB_E2E_BIG_MB=6144 cargo test --release e2e -- --nocapture` adds a
//! single file of that size (sparse on the sender's disk, real ciphertext on
//! the receiver's) to check memory stays flat regardless of file size.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use age::secrecy::SecretString;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::{endpoint::presets::Minimal, Endpoint, RelayMode, RelayUrl, SecretKey};

use crate::protocol::{self, SyncAck, SyncRequest};
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

fn peak_rss_mb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:")).map(|l| l.to_string()))
        .and_then(|l| l.split_whitespace().nth(1).and_then(|kb| kb.parse::<u64>().ok()))
        .map(|kb| kb / 1024)
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_backup_restore_versions_and_compat() {
    let root = std::env::temp_dir().join(format!("bb-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (mine, config_a) = (root.join("a/my-files"), root.join("a/config"));
    let (config_b, buddy_files_b) = (root.join("b/config"), root.join("b/buddy-files"));
    let restored = root.join("a/restored");
    for d in [&mine, &config_a, &config_b, &buddy_files_b, &restored] {
        std::fs::create_dir_all(d).unwrap();
    }

    crate::crypto::init(&SecretString::from(PASS.to_string()), crate::crypto::tests::TEST_ACCOUNT).unwrap();
    crate::index::open(&config_a).unwrap();
    crate::backup::init_spool(&config_a).await;
    let relay: RelayUrl = "https://relay.invalid".parse().unwrap();

    // Two endpoints that know each other's local address.
    let lookup_a = MemoryLookup::new();
    let lookup_b = MemoryLookup::new();
    let ep_b = endpoint(vec![protocol::ALPN.to_vec()], lookup_b.clone()).await;
    let ep_a = endpoint(vec![protocol::ALPN.to_vec()], lookup_a.clone()).await;
    lookup_a.add_endpoint_info(ep_b.addr());
    lookup_b.add_endpoint_info(ep_a.addr());
    let (a_id, b_id) = (ep_a.id(), ep_b.id());

    let pledge: PledgeBook = Arc::new(Mutex::new(HashMap::from([(
        a_id.to_string(),
        PledgeState { pledged_bytes: 1 << 40, received_bytes: 0 },
    )])));
    serve(ep_b.clone(), config_b.clone(), buddy_files_b.clone(), pledge.clone());

    // --- Files of awkward sizes, nested folders --------------------------
    let mut expected: HashMap<String, Vec<u8>> = HashMap::new();
    for (rel, n, seed) in [
        ("empty.txt", 0usize, 0u8),
        ("hello.txt", 17, 1),
        ("chunk/exact-64k.bin", 65536, 2),
        ("chunk/64k-plus-1.bin", 65537, 3),
        ("deep/a/b/c/medium.bin", 3_000_000, 4),
        ("photos/2024/img 001.jpg", 250_000, 5),
    ] {
        let data = pattern(n, seed);
        write(&mine, rel, &data);
        expected.insert(rel.to_string(), data);
    }
    // BB_E2E_MANY=N adds N small files (a photo-library-shaped folder) to
    // measure per-file overhead.
    let many: usize = std::env::var("BB_E2E_MANY").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    for i in 0..many {
        let data = pattern(2000 + i % 5000, (i % 251) as u8);
        write(&mine, &format!("many/{:03}/file-{i}.jpg", i / 1000), &data);
        expected.insert(format!("many/{:03}/file-{i}.jpg", i / 1000), data);
    }
    let big_mb: u64 = std::env::var("BB_E2E_BIG_MB").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    if big_mb > 0 {
        // Sparse: reads as zeros, costs no disk on the sender side.
        let f = std::fs::File::create(mine.join("big.img")).unwrap();
        f.set_len(big_mb * 1024 * 1024).unwrap();
    }

    // 1. First cycle sends everything.
    let t = std::time::Instant::now();
    // With a progress book: the entry exists while the cycle runs and is
    // gone afterwards, so the dashboard never shows a stuck progress bar.
    let progress_book: crate::backup::CycleProgressBook = Default::default();
    let stats = crate::backup::run_backup_cycle(&ep_a, &relay, &mine, b_id, Some(&progress_book)).await.unwrap();
    assert!(progress_book.lock().unwrap().is_empty(), "progress entry left behind after the cycle");
    let expected_files = expected.len() + usize::from(big_mb > 0);
    assert_eq!(stats.files_sent, expected_files, "first cycle: {stats:?}");
    assert_eq!(stats.files_failed, 0, "{stats:?}");
    // Relay is off in this test, so every byte is booked as direct.
    let traffic = stats.traffic.expect("a cycle that connected reports its traffic");
    assert_eq!(traffic.relay, 0, "{traffic:?}");
    assert!(traffic.direct >= stats.bytes_sent && stats.bytes_sent > 0, "{traffic:?} vs {}", stats.bytes_sent);
    eprintln!("first cycle: {} files in {:.1}s, peak RSS so far {} MB", stats.files_sent, t.elapsed().as_secs_f64(), peak_rss_mb());

    let stored = buddy_files_b.join(a_id.to_string());
    let (sent_count, sent_bytes) = crate::index::get().sent_summary(&b_id.to_string()).unwrap();
    assert_eq!(sent_count, expected_files);
    let on_disk: u64 = walkdir::WalkDir::new(&stored)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .map(|e| e.metadata().unwrap().len())
        .sum();
    assert_eq!(on_disk, sent_bytes, "index records exactly what the buddy stores");
    let staged_files = walkdir::WalkDir::new(stored.join(".incoming")).into_iter().flatten().filter(|e| e.file_type().is_file()).count();
    assert_eq!(staged_files, 0, "nothing left in upload staging");

    // 1b. A big file whose upload is cut partway resumes where it stopped.
    // (Files over RESUMABLE_MIN_BYTES — 1 MiB in tests — go resumably;
    // medium.bin above already went that way without a cut.)
    let resumable_data = pattern(5_000_000, 9);
    write(&mine, "video/clip.mov", &resumable_data);
    expected.insert("video/clip.mov".into(), resumable_data);
    crate::backup::TEST_CUT_AFTER_BYTES.store(2_000_000, std::sync::atomic::Ordering::Relaxed);
    let stats = crate::backup::run_backup_cycle(&ep_a, &relay, &mine, b_id, None).await.unwrap();
    crate::backup::TEST_CUT_AFTER_BYTES.store(0, std::sync::atomic::Ordering::Relaxed);
    assert_eq!((stats.files_sent, stats.files_failed), (0, 1), "cut upload: {stats:?}");
    let spooled = std::fs::read_dir(config_a.join("outgoing")).unwrap().count();
    assert_eq!(spooled, 2, "the local copy (.ct + .json) is kept to resume from");
    // Give the receiver a moment to notice the reset and flush its partial.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let stats = crate::backup::run_backup_cycle(&ep_a, &relay, &mine, b_id, None).await.unwrap();
    assert_eq!((stats.files_sent, stats.files_failed), (1, 0), "resumed upload: {stats:?}");
    let resumed_from = crate::backup::TEST_LAST_RESUME_OFFSET.load(std::sync::atomic::Ordering::Relaxed);
    assert!((1_000_000..5_000_000).contains(&resumed_from), "resumed partway, not from zero: {resumed_from}");
    assert_eq!(std::fs::read_dir(config_a.join("outgoing")).unwrap().count(), 0, "local copy removed once stored");
    let staged_files = walkdir::WalkDir::new(stored.join(".incoming")).into_iter().flatten().filter(|e| e.file_type().is_file()).count();
    assert_eq!(staged_files, 0, "partial moved into place, nothing left staged");
    eprintln!("cut upload resumed from byte {resumed_from}");

    // 1c. Cut again, but the file changes before the retry: the stale
    // copies on both sides are dropped and the new content goes in whole.
    write(&mine, "video/clip.mov", &pattern(4_000_000, 10));
    crate::backup::TEST_CUT_AFTER_BYTES.store(1_500_000, std::sync::atomic::Ordering::Relaxed);
    let stats = crate::backup::run_backup_cycle(&ep_a, &relay, &mine, b_id, None).await.unwrap();
    crate::backup::TEST_CUT_AFTER_BYTES.store(0, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(stats.files_failed, 1, "{stats:?}");
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let changed = pattern(4_500_000, 11);
    write(&mine, "video/clip.mov", &changed);
    expected.insert("video/clip.mov".into(), changed);
    crate::backup::TEST_LAST_RESUME_OFFSET.store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
    let stats = crate::backup::run_backup_cycle(&ep_a, &relay, &mine, b_id, None).await.unwrap();
    assert_eq!((stats.files_sent, stats.files_failed), (1, 0), "changed file: {stats:?}");
    assert_eq!(
        crate::backup::TEST_LAST_RESUME_OFFSET.load(std::sync::atomic::Ordering::Relaxed),
        u64::MAX,
        "a changed file must not resume from the old copy"
    );
    assert_eq!(std::fs::read_dir(config_a.join("outgoing")).unwrap().count(), 0);
    let staged_files = walkdir::WalkDir::new(stored.join(".incoming")).into_iter().flatten().filter(|e| e.file_type().is_file()).count();
    assert_eq!(staged_files, 0, "the old partial was discarded");

    // 2. Nothing changed: nothing sent, no connection needed.
    let t = std::time::Instant::now();
    let stats = crate::backup::run_backup_cycle(&ep_a, &relay, &mine, b_id, None).await.unwrap();
    assert_eq!((stats.files_sent, stats.files_deleted, stats.files_failed), (0, 0, 0));
    assert!(stats.connection.is_none(), "idle cycle shouldn't connect");
    let idle = t.elapsed();
    eprintln!("unchanged cycle: {:.0} ms", idle.as_secs_f64() * 1000.0);
    if big_mb > 0 {
        assert!(idle.as_secs() < 5, "unchanged big file must not be re-read: {idle:?}");
    }

    // 3. Touched but identical: re-hashed, not re-sent.
    let p = mine.join("hello.txt");
    let f = std::fs::File::options().write(true).open(&p).unwrap();
    f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5)).unwrap();
    drop(f);
    let stats = crate::backup::run_backup_cycle(&ep_a, &relay, &mine, b_id, None).await.unwrap();
    assert_eq!(stats.files_sent, 0, "same content, new mtime: {stats:?}");

    // 4. A real edit and a delete.
    let v2 = b"hello again, version two".to_vec();
    write(&mine, "hello.txt", &v2);
    let old_hello = expected.insert("hello.txt".into(), v2).unwrap();
    std::fs::remove_file(mine.join("photos/2024/img 001.jpg")).unwrap();
    expected.remove("photos/2024/img 001.jpg");
    let stats = crate::backup::run_backup_cycle(&ep_a, &relay, &mine, b_id, None).await.unwrap();
    assert_eq!((stats.files_sent, stats.files_deleted), (1, 1), "{stats:?}");

    // 5. Reconciliation agrees with the buddy.
    let rec = crate::backup::reconcile_with_buddy(&ep_a, &relay, b_id).await.unwrap();
    assert!(rec.missing_on_buddy.is_empty() && rec.unexpected_on_buddy.is_empty(), "{rec:?}");
    assert_eq!(rec.checked, expected.len() + usize::from(big_mb > 0));

    // 6. Restore everything; compare byte for byte.
    let pass = SecretString::from(PASS.to_string());
    let t = std::time::Instant::now();
    let r = crate::restore::run_restore(&ep_a, &relay, &pass, b_id, &restored).await.unwrap();
    eprintln!("restore: {} files in {:.1}s, peak RSS so far {} MB", r.files_restored, t.elapsed().as_secs_f64(), peak_rss_mb());
    assert_eq!(r.files_restored, expected.len() + usize::from(big_mb > 0));
    for (rel, data) in &expected {
        assert_eq!(&std::fs::read(restored.join(rel)).unwrap(), data, "restored {rel}");
    }
    if big_mb > 0 {
        let meta = std::fs::metadata(restored.join("big.img")).unwrap();
        assert_eq!(meta.len(), big_mb * 1024 * 1024);
        assert_eq!(
            crate::crypto::sha256_file(restored.join("big.img")).await.unwrap(),
            crate::crypto::sha256_file(mine.join("big.img")).await.unwrap()
        );
        std::fs::remove_file(restored.join("big.img")).unwrap();
    }
    // Deleted file is not restored as live.
    assert!(!restored.join("photos/2024/img 001.jpg").exists());

    // 7. The previous hello.txt is recoverable as a version.
    crate::restore::restore_version(&ep_a, &relay, &pass, b_id, &restored, "hello.txt", 1).await.unwrap();
    assert_eq!(std::fs::read(restored.join("hello.txt.v1.bak")).unwrap(), old_hello);

    // 7b. "Delete permanently": the deleted photo's copies go, and the
    // buddy refuses for a file that still exists.
    let listed = crate::restore::list_buddy_files(&ep_a, &relay, b_id).await.unwrap();
    assert!(listed.iter().any(|f| f.deleted && f.path == "photos/2024/img 001.jpg"), "deleted photo listed as recoverable first");
    crate::restore::purge_deleted(&ep_a, &relay, b_id, "photos/2024/img 001.jpg").await.unwrap();
    let listed = crate::restore::list_buddy_files(&ep_a, &relay, b_id).await.unwrap();
    assert!(!listed.iter().any(|f| f.path == "photos/2024/img 001.jpg"), "gone after delete permanently");
    let refused = crate::restore::purge_deleted(&ep_a, &relay, b_id, "hello.txt").await;
    assert!(refused.unwrap_err().to_string().contains("still exists"), "a live file is never purged");
    assert!(stored.join("hello.txt").exists());

    // 8. A buddy that hasn't updated (v1 client) can still send to us.
    let lookup_c = MemoryLookup::new();
    lookup_c.add_endpoint_info(ep_b.addr());
    let ep_c = endpoint(vec![protocol::ALPN.to_vec()], lookup_c).await;
    pledge.lock().unwrap().insert(ep_c.id().to_string(), PledgeState { pledged_bytes: 1 << 30, received_bytes: 0 });
    let legacy = age::encrypt(&age::scrypt::Recipient::new(SecretString::from(PASS.to_string())), b"from an old client").unwrap();
    {
        use sha2::{Digest, Sha256};
        let conn = ep_c.connect(iroh::EndpointAddr::new(b_id), protocol::ALPN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        protocol::write_frame(
            &mut send,
            &SyncRequest::Put {
                path: "old.txt".into(),
                ciphertext_len: legacy.len() as u64,
                ciphertext_sha256: hex::encode(Sha256::digest(&legacy)),
            },
        )
        .await
        .unwrap();
        send.write_all(&legacy).await.unwrap();
        send.finish().unwrap();
        let ack: SyncAck = protocol::read_frame(&mut recv).await.unwrap();
        assert!(ack.ok, "{ack:?}");
    }
    assert_eq!(std::fs::read(buddy_files_b.join(ep_c.id().to_string()).join("old.txt")).unwrap(), legacy);

    // 9. Sending to a buddy that hasn't updated (client ≤0.4): falls back
    // to the old upload format. The stand-in below behaves like the old
    // receive code: it drops a stream whose request it can't parse
    // (Hello, PutStream) and accepts the old Put.
    let old_store = root.join("old-buddy");
    std::fs::create_dir_all(&old_store).unwrap();
    let old_buddy = endpoint(vec![protocol::ALPN.to_vec()], MemoryLookup::new()).await;
    {
        let (ep, store) = (old_buddy.clone(), old_store.clone());
        tokio::spawn(async move {
            while let Some(incoming) = ep.accept().await {
                let store = store.clone();
                tokio::spawn(async move {
                    let Ok(conn) = async { incoming.accept()?.await }.await else { return };
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        let req: serde_json::Value = match protocol::read_frame(&mut recv).await {
                            Ok(v) => v,
                            Err(_) => continue,
                        };
                        match req["op"].as_str() {
                            Some("put") => {
                                use sha2::{Digest, Sha256};
                                let len = req["ciphertext_len"].as_u64().unwrap() as usize;
                                let mut body = vec![0u8; len];
                                recv.read_exact(&mut body).await.unwrap();
                                assert_eq!(hex::encode(Sha256::digest(&body)), req["ciphertext_sha256"].as_str().unwrap());
                                let dest = store.join(req["path"].as_str().unwrap());
                                std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
                                std::fs::write(dest, body).unwrap();
                                protocol::write_frame(&mut send, &SyncAck::ok()).await.unwrap();
                                send.finish().unwrap();
                            }
                            Some("ping") => {
                                protocol::write_frame(&mut send, &SyncAck::ok()).await.unwrap();
                                send.finish().unwrap();
                            }
                            // What an old client does with a request it
                            // can't parse: error out and drop the stream.
                            _ => drop((send, recv)),
                        }
                    }
                });
            }
        });
    }
    let lookup_d = MemoryLookup::new();
    lookup_d.add_endpoint_info(old_buddy.addr());
    let ep_d = endpoint(vec![protocol::ALPN.to_vec()], lookup_d).await;
    let t = std::time::Instant::now();
    let stats = crate::backup::run_backup_cycle(&ep_d, &relay, &mine, old_buddy.id(), None).await.unwrap();
    eprintln!("sending to an old buddy: {stats:?} in {:.1}s", t.elapsed().as_secs_f64());
    assert!(t.elapsed().as_secs() < 20, "fallback must not wait for a timeout");
    assert_eq!(stats.files_sent, expected.len(), "small files go via the old format: {stats:?}");
    if big_mb * 1024 * 1024 > protocol::LEGACY_PUT_MAX_BYTES {
        assert_eq!(stats.files_failed, 1);
        assert!(stats.failed_paths[0].reason.unwrap().contains("out of date"), "{stats:?}");
    }
    // What the old buddy stored decrypts with our key.
    let restored_old = root.join("restored-from-old");
    let (tx, done) = crate::crypto::decrypt_to_file(restored_old.join("x"));
    tx.send(Ok(std::fs::read(old_store.join("deep/a/b/c/medium.bin")).unwrap())).await.unwrap();
    drop(tx);
    done.await.unwrap().unwrap();
    assert_eq!(std::fs::read(restored_old.join("x")).unwrap(), expected["deep/a/b/c/medium.bin"]);

    eprintln!("peak RSS for the whole test: {} MB", peak_rss_mb());
    let _ = std::fs::remove_dir_all(&root);
}
