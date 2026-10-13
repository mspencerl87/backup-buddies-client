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

/// Every file and folder name the buddy keeps for us under `stored` is an
/// encrypted one (or the buddy's own bookkeeping), in live files and in
/// `.versions/` alike: no plaintext name from `plain` shows up anywhere.
fn assert_names_hidden(stored: &Path, plain: &[&str]) {
    let plain_parts: std::collections::HashSet<&str> =
        plain.iter().flat_map(|p| p.split('/')).collect();
    let mut seen = 0;
    let walk = walkdir::WalkDir::new(stored).min_depth(1).into_iter().filter_entry(|e| e.file_name() != ".incoming");
    for entry in walk {
        let entry = entry.unwrap();
        let name = entry.file_name().to_str().unwrap().to_string();
        if [".versions", ".retention-v1", crate::names::PREFIX].contains(&name.as_str()) {
            continue;
        }
        // A backup copy is "<remote name>.v<N>".
        let name = match name.rsplit_once(".v") {
            Some((base, slot)) if slot.parse::<u32>().is_ok() => base.to_string(),
            _ => name,
        };
        assert!(!plain_parts.contains(name.as_str()), "plaintext name on the buddy: {}", entry.path().display());
        assert!(
            name.len() >= 52 && name.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'v')),
            "not an encrypted name: {}",
            entry.path().display()
        );
        seen += 1;
    }
    assert!(seen > 0, "nothing stored under {}", stored.display());
}

/// Step 7e of the e2e test: a buddy holding a 0.13-style backup (every
/// file under its real path, plus a backup copy of one) gets moved to
/// encrypted names by an ordinary cycle.
async fn migrate_legacy_backup(
    root: &Path,
    ep_a: &Endpoint,
    lookup_a: &MemoryLookup,
    relay: &RelayUrl,
    mine: &Path,
    expected: &HashMap<String, Vec<u8>>,
    pass: &SecretString,
) {
    let (config_e, files_e) = (root.join("e/config"), root.join("e/buddy-files"));
    for d in [&config_e, &files_e] {
        std::fs::create_dir_all(d).unwrap();
    }
    let ep_e = endpoint(vec![protocol::ALPN.to_vec()], MemoryLookup::new()).await;
    lookup_a.add_endpoint_info(ep_e.addr());
    let e_id = ep_e.id();
    let pledge: PledgeBook = Arc::new(Mutex::new(HashMap::from([(
        ep_a.id().to_string(),
        PledgeState { pledged_bytes: 1 << 40, received_bytes: 0, account_id: None },
    )])));
    serve(ep_e.clone(), config_e, files_e.clone(), pledge);

    // What 0.13 left behind: plaintext paths on the buddy, index rows with
    // name scheme 0, and an older copy of hello.txt under .versions/.
    let idx = crate::index::get();
    let conn = ep_a.connect(iroh::EndpointAddr::new(e_id), protocol::ALPN).await.unwrap();
    for (i, rel) in expected.keys().chain(std::iter::once(&"hello.txt".to_string())).enumerate() {
        let abs = mine.join(rel);
        let size = std::fs::metadata(&abs).unwrap().len();
        let ciphertext_size = crate::backup::put_one_file(&conn, rel, &abs, size, None).await.unwrap();
        if i < expected.len() {
            let sha256 = crate::crypto::sha256_file(abs).await.unwrap();
            let entry = crate::index::SentEntry { size, sha256, ciphertext_size, name_scheme: crate::names::SCHEME_PLAIN };
            idx.record_sent(&e_id.to_string(), rel, &entry).unwrap();
        }
    }
    drop(conn);
    let stored = files_e.join(ep_a.id().to_string());
    assert!(stored.join("hello.txt").exists() && stored.join(".versions/hello.txt.v1").exists());

    let resends_before = idx.frequent_resends(7, 1, 0, 50).unwrap();

    // One ordinary cycle moves everything.
    // (BB_E2E_BIG_MB's big.img wasn't on the legacy buddy: it goes as new.)
    let big = usize::from(mine.join("big.img").exists());
    let stats = crate::backup::run_backup_cycle(ep_a, relay, mine, e_id, None).await.unwrap();
    assert_eq!((stats.files_sent, stats.names_hidden, stats.files_failed), (expected.len() + big, expected.len(), 0), "{stats:?}");
    assert_eq!(stats.files_deleted, 0, "old copies aren't reported as deleted files: {stats:?}");
    assert!(idx.old_names(&e_id.to_string()).unwrap().is_empty(), "every old copy deleted");
    assert_eq!(idx.frequent_resends(7, 1, 0, 50).unwrap(), resends_before, "hiding names isn't a re-send");

    // Live files only under n1/ now. The old copies stay under .versions/
    // with their real names until they expire (30 days), as documented.
    let top: Vec<String> = std::fs::read_dir(&stored).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    assert!(top.iter().all(|n| [".incoming", ".versions", "n1"].contains(&n.as_str())), "{top:?}");
    let tree: Vec<&str> = expected.keys().map(String::as_str).collect();
    assert_names_hidden(&stored.join("n1"), &tree);

    // Browse files lists each file once, by its real path, as live.
    let listed = crate::restore::list_buddy_files(ep_a, relay, e_id).await.unwrap();
    let mut paths: Vec<&str> = listed.iter().map(|f| f.path.as_str()).collect();
    paths.sort();
    let mut want = tree.clone();
    if big == 1 {
        want.push("big.img");
    }
    want.sort();
    assert_eq!(paths, want);
    assert!(listed.iter().all(|f| !f.deleted && crate::names::is_encrypted(&f.remote)));

    // Reconciliation is clean; History still finds the old copies.
    let rec = crate::backup::reconcile_with_buddy(ep_a, relay, e_id).await.unwrap();
    assert!(rec.missing_on_buddy.is_empty() && rec.unexpected_on_buddy.is_empty(), "{rec:?}");
    let versions = crate::restore::list_file_versions(ep_a, relay, e_id, "hello.txt").await.unwrap();
    assert_eq!(versions.len(), 2, "the moved-off copy and the older one: {versions:?}");
    let restored = root.join("e/restored");
    crate::restore::restore_version(ep_a, relay, pass, e_id, &restored, "hello.txt", 1).await.unwrap();
    assert_eq!(std::fs::read(restored.join("hello.txt.v1.bak")).unwrap(), expected["hello.txt"]);

    // Everything restores, byte for byte.
    let r = crate::restore::run_restore(ep_a, relay, pass, e_id, &restored).await.unwrap();
    assert_eq!(r.files_restored, expected.len() + big);
    for (rel, data) in expected {
        assert_eq!(&std::fs::read(restored.join(rel)).unwrap(), data, "restored {rel}");
    }

    // Done: the next cycle has nothing to do.
    let stats = crate::backup::run_backup_cycle(ep_a, relay, mine, e_id, None).await.unwrap();
    assert!(stats.connection.is_none() && stats.files_sent == 0, "{stats:?}");
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
        PledgeState { pledged_bytes: 1 << 40, received_bytes: 0, account_id: None },
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
    // The buddy sees no file or folder names.
    let tree: Vec<&str> = expected.keys().map(String::as_str).collect();
    assert_names_hidden(&stored, &tree);

    // 1a. "What your buddy sees": a peek returns the start of the file
    // exactly as stored (an age header, never the plaintext), and a file
    // shorter than the peek comes back whole.
    let listing = crate::restore::list_buddy_files(&ep_a, &relay, b_id).await.unwrap();
    let medium = listing.iter().find(|f| f.path == "deep/a/b/c/medium.bin").unwrap();
    let peeked = crate::restore::peek_buddy_file(&ep_a, &relay, b_id, &medium.remote, 256).await.unwrap();
    let on_disk = std::fs::read(stored.join(&medium.remote)).unwrap();
    assert_eq!(peeked[..], on_disk[..256], "peek returns the stored bytes");
    assert!(peeked.starts_with(b"age-encryption.org/v1"), "stored file starts with an age header");
    let plain = &expected["deep/a/b/c/medium.bin"];
    assert!(!on_disk.windows(64).any(|w| w == &plain[..64]), "plaintext isn't in the stored file");
    // (Even a 17-byte file is a few hundred bytes stored: age's header.)
    let hello = listing.iter().find(|f| f.path == "hello.txt").unwrap();
    let peeked = crate::restore::peek_buddy_file(&ep_a, &relay, b_id, &hello.remote, 4096).await.unwrap();
    assert_eq!(peeked, std::fs::read(stored.join(&hello.remote)).unwrap(), "short file comes back whole");

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
    // It was already on the buddy, so that counted as a re-send (the
    // dashboard's "keeps re-sending" list); first uploads don't.
    let resends = crate::index::get().frequent_resends(7, 1, 0, 10).unwrap();
    let paths: Vec<(&str, u64, u64)> = resends.iter().map(|r| (r.path.as_str(), r.sends, r.size)).collect();
    assert_eq!(paths, vec![("video/clip.mov", 1, 4_500_000)]);
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

    // 3b. A name too long to encrypt within filename limits is refused
    // with a reason (once in Activity, every cycle in the failed list),
    // never truncated.
    let long_name = format!("long/{}.txt", "n".repeat(130));
    write(&mine, &long_name, b"long name");
    let stats = crate::backup::run_backup_cycle(&ep_a, &relay, &mine, b_id, None).await.unwrap();
    assert_eq!((stats.files_sent, stats.files_failed), (0, 1), "{stats:?}");
    assert!(stats.failed_paths[0].reason.unwrap().contains("too long"), "{stats:?}");
    assert_eq!(stats.new_refusals.len(), 1, "{stats:?}");
    let stats = crate::backup::run_backup_cycle(&ep_a, &relay, &mine, b_id, None).await.unwrap();
    assert_eq!((stats.files_failed, stats.new_refusals.len()), (1, 0), "said once: {stats:?}");
    std::fs::remove_dir_all(mine.join("long")).unwrap();

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
    assert!(stored.join(crate::names::encrypt_path("hello.txt").unwrap()).exists());

    // 7c. Still no names after overwrites, deletes and backup copies.
    let mut tree: Vec<&str> = expected.keys().map(String::as_str).collect();
    tree.push("photos/2024/img 001.jpg");
    assert_names_hidden(&stored, &tree);
    assert!(stored.join(".versions").exists(), "backup copies were checked too");

    // 7d. Restore one folder (what the dashboard does: pick from the
    // listing by real path).
    let folder = root.join("a/restored-folder");
    let chunk: Vec<_> = crate::restore::list_buddy_files(&ep_a, &relay, b_id)
        .await
        .unwrap()
        .into_iter()
        .filter(|f| !f.deleted && f.path.starts_with("chunk/"))
        .collect();
    assert_eq!(chunk.len(), 2);
    let r = crate::restore::restore_selected(&ep_a, &relay, &pass, b_id, &folder, &chunk, None).await.unwrap();
    assert_eq!(r.files_restored, 2);
    for rel in ["chunk/exact-64k.bin", "chunk/64k-plus-1.bin"] {
        assert_eq!(std::fs::read(folder.join(rel)).unwrap(), expected[rel], "restored {rel}");
    }

    // 7e. A backup made before 0.14.0 (plaintext names on the buddy)
    // moves to encrypted names: each file is re-sent under its new name,
    // then its old copy is deleted. Needs nothing new from the buddy.
    migrate_legacy_backup(&root, &ep_a, &lookup_a, &relay, &mine, &expected, &pass).await;

    // 8. A buddy that hasn't updated (v1 client) can still send to us.
    let lookup_c = MemoryLookup::new();
    lookup_c.add_endpoint_info(ep_b.addr());
    let ep_c = endpoint(vec![protocol::ALPN.to_vec()], lookup_c).await;
    pledge.lock().unwrap().insert(ep_c.id().to_string(), PledgeState { pledged_bytes: 1 << 30, received_bytes: 0, account_id: None });
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
    let medium = crate::names::encrypt_path("deep/a/b/c/medium.bin").unwrap();
    tx.send(Ok(std::fs::read(old_store.join(medium)).unwrap())).await.unwrap();
    drop(tx);
    done.await.unwrap().unwrap();
    assert_eq!(std::fs::read(restored_old.join("x")).unwrap(), expected["deep/a/b/c/medium.bin"]);

    eprintln!("peak RSS for the whole test: {} MB", peak_rss_mb());
    let _ = std::fs::remove_dir_all(&root);
}

/// Protocol v5: the buddy stores a chunked backup's repository files, by
/// kind and id, checks each against its name, counts them against the
/// pledge, and keeps them out of the whole-file listings.
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
    // the same reason a whole-file upload gets.
    let big = pattern(2_500_000, 5);
    let err = crate::repo::write(&conn, Pack, &id_of(&big), &big).await.unwrap_err();
    let refused = err.chain().any(|c| {
        matches!(c.downcast_ref::<iroh::endpoint::WriteError>(),
            Some(iroh::endpoint::WriteError::Stopped(code)) if protocol::PutRejectReason::from_code(code.into_inner()) == Some(protocol::PutRejectReason::PledgeExceeded))
    }) || err.to_string().contains("pledge");
    assert!(refused, "expected a pledge refusal, got {err:?}");

    // Hidden from the whole-file listing, counted in usage from disk.
    let sender_dir = buddy_files_b.join(&a_id);
    assert!(crate::receive::list_sender_files(&sender_dir).await.is_empty());
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

/// Chunked backups end to end against a real buddy: a snapshot of the
/// backup folder lands in the buddy's repository; renames and moves send
/// next to nothing; a 1-byte edit in a big file sends about one chunk; the
/// data reads back through rustic with the passphrase-derived key; and a
/// full pledge refuses the write.
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
    let cycle = || crate::chunked::run_chunked_cycle(&ep_a, &relay, &mine, b_id, None);
    let sender_dir = buddy_files_b.join(&a_id);

    // 1. First backup: everything goes, into the repository only.
    let s = cycle().await.unwrap();
    assert_eq!(s.files_sent, 21);
    assert!(s.bytes_sent > 32_500_000, "sent {}", s.bytes_sent);
    assert!(crate::receive::list_sender_files(&sender_dir).await.is_empty(), "no whole files");
    assert!(crate::repo::repo_size(&sender_dir).await > 32_500_000);

    // Moving off whole files: copies sent the old way (recorded in an
    // index of their own here, since the real one is shared with the
    // whole-file e2e test) are deleted on the buddy, so they're kept
    // there as 30-day backup copies, and forgotten here.
    let idx = crate::index::Index::open_at(&config_a.join("retire-test.sqlite")).unwrap();
    let conn = ep_a.connect(ep_b.addr(), protocol::ALPN).await.unwrap();
    for rel in ["photos/2024/img01.jpg", "photos/2024/img02.jpg"] {
        let remote = crate::names::encrypt_path(rel).unwrap();
        let abs = mine.join(rel);
        let size = std::fs::metadata(&abs).unwrap().len();
        let ciphertext_size = crate::backup::put_one_file(&conn, &remote, &abs, size, None).await.unwrap();
        let entry = crate::index::SentEntry {
            size,
            sha256: String::new(),
            ciphertext_size,
            name_scheme: crate::names::SCHEME_N1,
        };
        idx.record_sent(&b_id.to_string(), rel, &entry).unwrap();
    }
    assert_eq!(crate::receive::list_sender_files(&sender_dir).await.len(), 2);
    crate::chunked::retire_whole_files(&idx, &ep_a, &relay, b_id, &conn).await;
    let whole = crate::receive::list_sender_files(&sender_dir).await;
    assert!(whole.len() == 2 && whole.iter().all(|f| f.deleted), "whole files retired: {whole:?}");
    assert!(idx.sent_entries(&b_id.to_string()).unwrap().is_empty());

    // 2. Nothing changed, but retention is due right after the first
    // snapshot: it runs (prune finds nothing), sending no files.
    let s = cycle().await.unwrap();
    assert_eq!((s.files_sent, s.files_deleted), (0, 0));
    assert!(s.traffic.is_some(), "connected for retention");
    // 3. Still nothing changed and retention is done: fully idle.
    let s = cycle().await.unwrap();
    assert!(s.traffic.is_none(), "idle cycles don't connect");

    // 4. Rename the big file and move the photos: next to nothing is sent.
    std::fs::rename(mine.join("videos/clip.bin"), mine.join("videos/renamed.bin")).unwrap();
    std::fs::rename(mine.join("photos/2024"), mine.join("photos/holiday")).unwrap();
    let s = cycle().await.unwrap();
    assert_eq!((s.files_sent, s.files_deleted), (21, 21), "21 new paths, 21 gone");
    assert!(s.bytes_sent < 200_000, "a rename sent {} bytes", s.bytes_sent);
    eprintln!("chunked: renaming 32 MB + moving 20 photos sent {} bytes", s.bytes_sent);

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
    let buddy = b_id.to_string();
    assert!(crate::chunked::has_repo(&buddy));
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
    let stats = crate::restore::restore_selected(
        &ep_a,
        &relay,
        &SecretString::from(PASS.to_string()),
        b_id,
        &restored_dir,
        &listing.files,
        None,
    )
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
    let versions = crate::restore::list_file_versions(&ep_a, &relay, b_id, "videos/renamed.bin").await.unwrap();
    assert_eq!(versions.len(), 1, "{versions:?}");
    crate::restore::restore_version(&ep_a, &relay, &SecretString::from(PASS.to_string()), b_id, &restored_dir, "videos/renamed.bin", 1)
        .await
        .unwrap();
    assert_eq!(std::fs::read(restored_dir.join("videos/renamed.bin.v1.bak")).unwrap(), big);
    let versions = crate::restore::list_file_versions(&ep_a, &relay, b_id, "photos/holiday/img00.jpg").await.unwrap();
    assert_eq!(versions.len(), 1);
    crate::restore::restore_version(&ep_a, &relay, &SecretString::from(PASS.to_string()), b_id, &restored_dir, "photos/holiday/img00.jpg", 1)
        .await
        .unwrap();
    assert_eq!(std::fs::read(restored_dir.join("photos/holiday/img00.jpg.v1.bak")).unwrap(), noise(50_000, 100));
    // "Delete permanently" isn't offered for chunked backups.
    assert!(crate::restore::purge_deleted(&ep_a, &relay, b_id, "photos/holiday/img00.jpg").await.is_err());

    // "What your buddy sees": a pack's first bytes, as stored (encrypted).
    let first = &listing.packs[0];
    let peek = crate::restore::peek_buddy_file(&ep_a, &relay, b_id, &first.remote, 256).await.unwrap();
    assert_eq!(peek.len() as u64, first.size.min(256));

    // 6. A buddy whose pledge is full refuses the next pack, and the cycle
    // says so in the same words a whole-file refusal uses.
    pledge.lock().unwrap().get_mut(&a_id).unwrap().pledged_bytes = 1;
    write(&mine, "new.bin", &noise(2_000_000, 7));
    let err = cycle().await.unwrap_err();
    assert!(err.to_string().contains("pledge"), "got: {err:#}");

    let _ = std::fs::remove_dir_all(&root);
}
