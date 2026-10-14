// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

//! The backup's encryption key, from the passphrase.
//!
//! The slow passphrase step (scrypt) runs once at startup. The chunked
//! backup repository's master key is a labelled hash of its output, so the
//! passphrase (plus a device token on the same account, for the salt)
//! still recovers everything on a rebuilt device, and no restic key file
//! is ever written or needed.

use std::sync::OnceLock;

use anyhow::Result;
use secrecy::{ExposeSecret, SecretString};

// The key derivation. log_n=18, r=8 is scrypt's recommended interactive
// strength (256 MiB of RAM, ~1s, once at startup). The salt is the account
// id, so every device on an account derives the same key from the same
// passphrase (a rebuilt device restores with the passphrase and a device
// token on the same account), while no two accounts share a key: an
// attacker holding ciphertext has to guess passphrases one account at a
// time, rather than precompute one table of guesses that works against
// everyone.
const KDF_LOG_N: u8 = 18;
const KDF_R: u32 = 8;
const KDF_P: u32 = 1;
// "file-key" because the same scrypt output once keyed the whole-file
// backups too; changing it now would orphan every repository.
const KDF_SALT_PREFIX: &str = "backup-buddies/file-key/v2/";

struct Keys {
    /// Master key of the chunked-backup repository (see chunked.rs).
    repo_key: [u8; 64],
}

static KEYS: OnceLock<Keys> = OnceLock::new();

/// Derives the repository key from the passphrase and account id. Call
/// once at startup, before any backup or restore; later calls are no-ops.
pub fn init(passphrase: &SecretString, account_id: &str) -> Result<()> {
    if KEYS.get().is_some() {
        return Ok(());
    }
    let salt = format!("{KDF_SALT_PREFIX}{account_id}");
    let mut secret = derive_secret(passphrase, salt.as_bytes());
    let repo_key = labelled_key(REPO_KEY_LABEL, &secret);
    secret.fill(0);
    let _ = KEYS.set(Keys { repo_key });
    Ok(())
}

/// The slow passphrase step.
fn derive_secret(passphrase: &SecretString, salt: &[u8]) -> [u8; 32] {
    let mut secret = [0u8; 32];
    let params = scrypt::Params::new(KDF_LOG_N, KDF_R, KDF_P, 32).expect("valid scrypt params");
    scrypt::scrypt(passphrase.expose_secret().as_bytes(), salt, &params, &mut secret)
        .expect("32-byte output is valid");
    secret
}

/// Domain-separates the chunked-backup repository's master key from
/// anything else derived from the same scrypt output. Changing it (or the
/// scrypt salt) orphans every repository already on a buddy.
const REPO_KEY_LABEL: &[u8] = b"backup-buddies/repo-key/v1\0";

/// 64 bytes for `label` from the scrypt output. The input is already a
/// uniformly random key, so one SHA-512 is a sound derivation (HKDF's
/// extract step adds nothing here).
fn labelled_key(label: &[u8], secret: &[u8; 32]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(label);
    hasher.update(secret);
    let mut key = [0u8; 64];
    key.copy_from_slice(&hasher.finalize());
    key
}

/// The chunked-backup repository's master key: AES-256 key, then the
/// Poly1305-AES k and r, in the layout rustic_core's MasterKey takes.
pub(crate) fn repo_key() -> &'static [u8; 64] {
    &KEYS.get().expect("crypto::init must run at startup").repo_key
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // The key lives in a process-wide OnceLock and tests share a process,
    // so every test (here and in e2e_tests) uses this same passphrase.
    pub(crate) const TEST_PASSPHRASE: &str = "an end to end test passphrase";
    pub(crate) const TEST_ACCOUNT: &str = "00000000-0000-4000-8000-000000000001";

    #[test]
    fn repo_key_comes_from_the_passphrase_and_account() {
        let pass = SecretString::from(TEST_PASSPHRASE.to_string());
        init(&pass, TEST_ACCOUNT).unwrap();
        let secret = derive_secret(&pass, format!("{KDF_SALT_PREFIX}{TEST_ACCOUNT}").as_bytes());
        assert_eq!(&labelled_key(REPO_KEY_LABEL, &secret), repo_key(), "re-derivable on a rebuilt device");
        assert!(!repo_key().windows(32).any(|w| w == secret), "the scrypt output isn't used as is");
        let other = derive_secret(&pass, format!("{KDF_SALT_PREFIX}00000000-0000-4000-8000-000000000002").as_bytes());
        assert_ne!(&labelled_key(REPO_KEY_LABEL, &other), repo_key(), "another account, another key");
    }
}
