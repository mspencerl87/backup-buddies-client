// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

//! The old per-buddy JSON manifest format (`manifest-<buddy>.json`), kept
//! only so `index.rs` can import it once when upgrading from client ≤0.4.x.
//! Everything live is in the SQLite index now.

use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct LegacyManifestEntry {
    pub size: u64,
    pub sha256: String,
    /// Missing in very old manifests; imported as 0 and corrected the next
    /// time that file is sent.
    #[serde(default)]
    pub ciphertext_size: u64,
}

#[derive(Debug, Deserialize)]
pub struct LegacyManifest {
    pub entries: HashMap<String, LegacyManifestEntry>,
}
