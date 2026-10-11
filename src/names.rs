// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

//! File and folder names as a buddy stores them.
//!
//! Until 0.14.0 a buddy stored our files under their real relative paths
//! (`Photos/2024/IMG_0001.jpg`), so only the contents were hidden. Now
//! every path component is encrypted on its own, the way rclone's crypt
//! remote does it: `n1/<name>/<name>/<name>`. Each name is encrypted
//! deterministically, so a file always has the same remote name and the
//! buddy's side (overwrite in place, version slots, delete, list, purge)
//! keeps working unchanged: it only ever treats paths as opaque strings,
//! which is also why this needs no buddy upgrade.
//!
//! - Cipher: AES-SIV (RFC 5297). Deterministic like rclone's EME, and also
//!   authenticated, so a name that was tampered with or made with another
//!   key fails to decrypt instead of decrypting to garbage.
//! - Names are padded to a multiple of 16 bytes first (rclone does the
//!   same), so a buddy sees name lengths only in 16-byte steps.
//! - Like rclone, each name is encrypted independently of its folder:
//!   `2024` under Photos and under Taxes give the same remote name.
//! - Encoding: base32hex (RFC 4648), lowercase, no padding, rclone's
//!   default. Only [0-9a-v], so it survives case-insensitive filesystems
//!   (buddies store on SMB/NFS shares, Windows and macOS disks), and it
//!   can't collide with the buddy's own `.versions` / `.incoming` folders.
//! - `n1` marks name scheme 1. Anything else on a buddy is a plaintext path
//!   from a client before 0.14.0, still restorable until it's re-sent (see
//!   backup.rs), and leaves room for a scheme 2.
//!
//! A buddy still sees sizes, how deep folders go and how many entries
//! each has, how many files there are, and when they change.
//!
//! Changing the key derivation (crypto.rs), the padding, the encoding or
//! the cipher orphans every name already on a buddy.

use aes_siv::KeyInit;
use aes_siv::siv::Aes256Siv;

/// Top folder on the buddy for paths with encrypted names.
pub const PREFIX: &str = "n1";

/// How a path on a buddy is named (index.rs's `sent.name_scheme`).
pub const SCHEME_PLAIN: u8 = 0;
pub const SCHEME_N1: u8 = 1;

const BLOCK: usize = 16;
const TAG: usize = 16;

/// Longest file or folder name that can be backed up, in bytes (UTF-8, so
/// fewer characters for accented or non-Latin names). 127 pads to 128,
/// plus the 16-byte tag is 144 bytes, 231 characters of base32: under the
/// usual 255-byte filename limit with room for the buddy's `.vN` suffix on
/// backup copies. Longer names are refused rather than truncated.
pub const MAX_NAME_BYTES: usize = 127;

/// Longest whole remote path. Linux allows 4096 bytes per path; this
/// leaves room for the buddy's own folder, our node id, `.versions/` and
/// a `.vN` suffix in front of and after it.
const MAX_REMOTE_PATH: usize = 3800;

const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";

/// Why a file can't be backed up with encrypted names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    NameTooLong,
    PathTooLong,
}

impl NameError {
    /// The failed-file reason the dashboard and Activity show.
    pub fn message(self) -> &'static str {
        match self {
            NameError::NameTooLong => {
                "a file or folder name in its path is too long to back up with hidden names (over 127 bytes) — shorten it"
            }
            NameError::PathTooLong => "its path is too long to back up with hidden names (folders nested too deep)",
        }
    }
}

/// Length of one encrypted name, before encoding: padded name plus tag.
fn sealed_len(name_bytes: usize) -> usize {
    (name_bytes / BLOCK + 1) * BLOCK + TAG
}

fn encoded_len(bytes: usize) -> usize {
    (bytes * 8).div_ceil(5)
}

/// Whether `rel` can be backed up with encrypted names, without doing the
/// encryption: what a backup cycle asks of every file.
pub fn check(rel: &str) -> Result<(), NameError> {
    let mut total = PREFIX.len();
    for part in rel.split('/') {
        if part.len() > MAX_NAME_BYTES {
            return Err(NameError::NameTooLong);
        }
        total += 1 + encoded_len(sealed_len(part.len()));
    }
    if total > MAX_REMOTE_PATH {
        return Err(NameError::PathTooLong);
    }
    Ok(())
}

fn cipher() -> Aes256Siv {
    Aes256Siv::new_from_slice(crate::crypto::name_key()).expect("64-byte AES-SIV key")
}

/// Plaintext relative path → the path a buddy stores it under.
pub fn encrypt_path(rel: &str) -> Result<String, NameError> {
    check(rel)?;
    let mut cipher = cipher();
    let mut out = String::from(PREFIX);
    for part in rel.split('/') {
        let pad = BLOCK - part.len() % BLOCK;
        let mut padded = Vec::with_capacity(part.len() + pad);
        padded.extend_from_slice(part.as_bytes());
        padded.resize(part.len() + pad, pad as u8);
        let sealed = cipher.encrypt(NO_HEADERS, &padded).expect("AES-SIV encryption doesn't fail");
        out.push('/');
        out.push_str(&encode(&sealed));
    }
    Ok(out)
}

/// The path a buddy stores `rel` under, for an index row with `scheme`.
pub fn remote_path(rel: &str, scheme: u8) -> Result<String, NameError> {
    if scheme == SCHEME_PLAIN { Ok(rel.to_string()) } else { encrypt_path(rel) }
}

const NO_HEADERS: [&[u8]; 0] = [];

/// A path from a buddy's file list, read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    /// Stored with encrypted names; this is the real path.
    Hidden(String),
    /// Stored under its real path by a client before 0.14.0.
    Plain(String),
    /// Under `n1/` but doesn't decrypt with our key: another passphrase or
    /// account, or damaged on the buddy's side.
    Unreadable,
}

impl Decoded {
    /// The real path, or the placeholder the dashboard shows for a name
    /// that can't be decrypted (with its remote path, so two of them stay
    /// apart and can still be fetched).
    pub fn display(&self, remote: &str) -> String {
        match self {
            Decoded::Hidden(p) | Decoded::Plain(p) => p.clone(),
            Decoded::Unreadable => {
                format!("{UNREADABLE_FOLDER}/{}", remote.strip_prefix("n1/").unwrap_or(remote))
            }
        }
    }
}

/// Where Browse files lists names that can't be decrypted.
pub const UNREADABLE_FOLDER: &str = "(names that can't be decrypted)";

/// Whether a remote path uses encrypted names (rather than being a
/// plaintext path from before 0.14.0).
pub fn is_encrypted(remote: &str) -> bool {
    remote.strip_prefix(PREFIX).is_some_and(|rest| rest.starts_with('/'))
}

/// Where a path the dashboard shows (and sends back) may be stored on the
/// buddy, most likely first: its encrypted name, then its plaintext name
/// in case it was sent before 0.14.0 and hasn't moved yet (or only its
/// backup copies are left there). A placeholder for a name that can't be
/// decrypted maps straight back to its remote path.
pub fn remote_candidates(path: &str) -> Vec<String> {
    if let Some(rest) = path.strip_prefix(UNREADABLE_FOLDER).and_then(|r| r.strip_prefix('/')) {
        return vec![format!("{PREFIX}/{rest}")];
    }
    let mut out = Vec::with_capacity(2);
    if let Ok(remote) = encrypt_path(path) {
        out.push(remote);
    }
    out.push(path.to_string());
    out
}

pub fn decrypt_path(remote: &str) -> Decoded {
    let Some(rest) = remote.strip_prefix("n1/") else {
        return Decoded::Plain(remote.to_string());
    };
    let mut cipher = cipher();
    let mut out = String::with_capacity(rest.len() / 2);
    for part in rest.split('/') {
        match decrypt_name(&mut cipher, part) {
            Some(name) => {
                if !out.is_empty() {
                    out.push('/');
                }
                out.push_str(&name);
            }
            None => return Decoded::Unreadable,
        }
    }
    Decoded::Hidden(out)
}

fn decrypt_name(cipher: &mut Aes256Siv, encoded: &str) -> Option<String> {
    let sealed = decode(encoded)?;
    if sealed.len() < TAG + BLOCK || !(sealed.len() - TAG).is_multiple_of(BLOCK) {
        return None;
    }
    let mut padded = cipher.decrypt(NO_HEADERS, &sealed).ok()?;
    let pad = *padded.last()? as usize;
    if pad == 0 || pad > BLOCK || padded[padded.len() - pad..].iter().any(|&b| b as usize != pad) {
        return None;
    }
    padded.truncate(padded.len() - pad);
    let name = String::from_utf8(padded).ok()?;
    // Authenticated, so only we could have made it; still never hand back
    // something that would step outside the restore folder.
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']) {
        return None;
    }
    Some(name)
}

fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(encoded_len(bytes.len()));
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Accepts either case, in case a buddy's filesystem changed it.
fn decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'v' => c - b'a' + 10,
            b'A'..=b'V' => c - b'A' + 10,
            _ => return None,
        };
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() {
        crate::crypto::init(
            &age::secrecy::SecretString::from(crate::crypto::tests::TEST_PASSPHRASE.to_string()),
            crate::crypto::tests::TEST_ACCOUNT,
        )
        .unwrap();
    }

    #[test]
    fn round_trips_and_is_deterministic() {
        setup();
        for rel in ["a", "hello.txt", "Photos/2024/IMG_0001.jpg", "deep/a/b/c/d/e/f.bin", "spaces and ünïcödé/日本語.txt"] {
            let remote = encrypt_path(rel).unwrap();
            assert_eq!(remote, encrypt_path(rel).unwrap(), "same name, same remote name");
            assert_eq!(decrypt_path(&remote), Decoded::Hidden(rel.to_string()));
            assert_eq!(remote.split('/').count(), rel.split('/').count() + 1, "one remote name per component");
        }
    }

    #[test]
    fn no_plaintext_and_only_base32hex() {
        setup();
        let remote = encrypt_path("Photos/2024/IMG_0001.jpg").unwrap();
        let mut parts = remote.split('/');
        assert_eq!(parts.next(), Some(PREFIX));
        for part in parts {
            assert!(part.bytes().all(|c| ALPHABET.contains(&c)), "{part}");
            for word in ["photos", "2024", "img", "jpg"] {
                assert!(!part.contains(word), "{part} contains {word}");
            }
        }
    }

    #[test]
    fn names_are_independent_of_their_folder() {
        // rclone's behaviour: the buddy can match names across folders,
        // but a folder's remote prefix never depends on what's above it.
        setup();
        let a = encrypt_path("Photos/2024").unwrap();
        let b = encrypt_path("Taxes/2024").unwrap();
        assert_ne!(a.split('/').nth(1), b.split('/').nth(1));
        assert_eq!(a.split('/').nth(2), b.split('/').nth(2));
    }

    #[test]
    fn lengths_only_show_in_16_byte_steps() {
        setup();
        let len = |n: usize| encrypt_path(&"x".repeat(n)).unwrap().len();
        assert_eq!(len(1), len(15));
        assert!(len(16) > len(15));
        assert_eq!(len(16), len(31));
    }

    #[test]
    fn long_names_are_refused_not_truncated() {
        setup();
        let longest = "é".repeat(MAX_NAME_BYTES / 2) + "x"; // 127 bytes
        let remote = encrypt_path(&longest).unwrap();
        let name = remote.rsplit('/').next().unwrap();
        assert_eq!(name.len(), 231);
        assert!(name.len() + ".v2".len() <= 255);
        assert_eq!(decrypt_path(&remote), Decoded::Hidden(longest.clone()));
        assert_eq!(encrypt_path(&format!("{longest}y")), Err(NameError::NameTooLong));
        assert_eq!(check(&format!("ok/{longest}y/ok")), Err(NameError::NameTooLong));
        // Deep enough to pass PATH_MAX on the buddy.
        let deep = vec!["x".repeat(100); 30].join("/");
        assert_eq!(check(&deep), Err(NameError::PathTooLong));
        // check() and the real thing agree on length.
        let fits = vec!["x".repeat(100); 15].join("/");
        assert!(check(&fits).is_ok() && encrypt_path(&fits).unwrap().len() <= MAX_REMOTE_PATH);
    }

    #[test]
    fn tampered_or_foreign_names_fail_cleanly() {
        setup();
        let remote = encrypt_path("Photos/IMG_0001.jpg").unwrap();
        let last = remote.rsplit('/').next().unwrap();
        // Flip one character of the last name.
        let flipped = match last.strip_prefix('0') { Some(rest) => format!("1{rest}"), None => format!("0{}", &last[1..]) };
        let tampered = format!("{}/{flipped}", &remote[..remote.len() - last.len() - 1]);
        assert_eq!(decrypt_path(&tampered), Decoded::Unreadable);
        // Another key (a different passphrase or account) can't read it.
        let mut other = Aes256Siv::new_from_slice(&[7u8; 64]).unwrap();
        let foreign = format!("n1/{}", encode(&other.encrypt(NO_HEADERS, &[b'a'; 16]).unwrap()));
        assert_eq!(decrypt_path(&foreign), Decoded::Unreadable);
        // Not base32, too short to hold a tag, or empty: unreadable, not a
        // panic.
        for bad in ["n1/xyz!", "n1/00", "n1/", "n1//x"] {
            assert_eq!(decrypt_path(bad), Decoded::Unreadable, "{bad}");
        }
        assert_eq!(Decoded::Unreadable.display(&tampered), format!("{UNREADABLE_FOLDER}/{}", &tampered[3..]));
    }

    #[test]
    fn plaintext_paths_from_older_clients_pass_through() {
        setup();
        assert_eq!(decrypt_path("Photos/IMG_0001.jpg"), Decoded::Plain("Photos/IMG_0001.jpg".into()));
        assert_eq!(remote_path("Photos/IMG_0001.jpg", SCHEME_PLAIN).unwrap(), "Photos/IMG_0001.jpg");
        assert!(remote_path("Photos/IMG_0001.jpg", SCHEME_N1).unwrap().starts_with("n1/"));
    }

    #[test]
    fn base32_round_trips_and_ignores_case() {
        for n in 0..40 {
            let bytes: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            let s = encode(&bytes);
            assert_eq!(s.len(), encoded_len(n as usize));
            assert_eq!(decode(&s).unwrap(), bytes);
            assert_eq!(decode(&s.to_uppercase()).unwrap(), bytes);
        }
    }
}
