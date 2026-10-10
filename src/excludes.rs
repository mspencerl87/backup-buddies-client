// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 Spencer LeBlanc

//! The exclude list: which files in BACKUP_DIR are never backed up.
//!
//! Patterns follow Syncthing's `.stignore` rules, so anyone who has used
//! that already knows them:
//!
//! - one pattern per line; blank lines and lines starting with `//` are
//!   ignored, and so are `# ` (hash and space) ones, since people write
//!   those out of habit. `#recycle`, with no space, is still a pattern
//! - `*` matches anything except `/`, `**` matches anything including `/`,
//!   `?` one character, `[a-z]` a range, `{a,b}` either
//! - a pattern matches at any depth (`*.pst` catches `mail/old.pst`) unless
//!   it starts with `/`, which ties it to the top of BACKUP_DIR
//! - a pattern that matches a folder excludes everything inside it
//! - `!` in front re-includes; the **first** matching line wins
//! - `(?i)` in front makes the pattern case-insensitive
//!
//! The person's own list lives in `DATA_DIR/excludes.txt` and is re-read
//! every cycle, so edits apply without a restart. A built-in list of poor
//! fits (see DEFAULTS) is checked after it, so a `!` line there can bring
//! back any one default, and `DEFAULT_EXCLUDES=off` drops them all.
//!
//! Excluding a file that was already backed up is mirrored like a delete:
//! the buddy keeps the old content as a backup copy for 30 days, then it's
//! gone (see receive.rs's handle_delete).

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, Result};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

pub const FILE_NAME: &str = "excludes.txt";

/// Built-in excludes: files that re-send whole on every small change, can't
/// be copied consistently while in use, or are regenerated anyway. Kept
/// conservative: anything a person might reasonably mean to back up (photo
/// catalogs, encrypted containers, Access databases, VM exports like .xva
/// or .ova) is left out of this list, since excluding it silently would
/// cost them their only off-site copy.
pub const DEFAULTS: &[(&str, &[&str])] = &[
    (
        "Outlook mail stores (re-sent whole after every new email; OST is a cache of the server)",
        &["(?i)*.pst", "(?i)*.ost"],
    ),
    (
        "Live databases and their journals (copied mid-write, may not open on restore)",
        &[
            "(?i)*.db",
            "(?i)*.db-wal",
            "(?i)*.db-shm",
            "(?i)*.db-journal",
            "(?i)*.sqlite",
            "(?i)*.sqlite3",
            "(?i)*.sqlite-wal",
            "(?i)*.sqlite-shm",
            "(?i)*.sqlite-journal",
            "(?i)*.mdf",
            "(?i)*.ndf",
            "(?i)*.ldf",
            "(?i)*.ibd",
            "(?i)*.ldb",
            "(?i)*.laccdb",
        ],
    ),
    (
        "Virtual machine disks, checkpoints and memory (may not boot on restore; back up an export instead)",
        &[
            "(?i)*.vmdk",
            "(?i)*.vhd",
            "(?i)*.vhdx",
            "(?i)*.avhd",
            "(?i)*.avhdx",
            "(?i)*.vdi",
            "(?i)*.qcow",
            "(?i)*.qcow2",
            "(?i)*.hds",
            "(?i)*.vmem",
            "(?i)*.vmsn",
            "(?i)*.vmss",
            "(?i)*.vmrs",
        ],
    ),
    (
        "Temporary, lock and half-downloaded files",
        &[
            "(?i)*.tmp",
            "~$*",
            ".~lock.*#",
            "*.swp",
            "(?i)*.part",
            "(?i)*.partial",
            "(?i)*.crdownload",
        ],
    ),
    (
        "System files, trash and snapshot folders",
        &[
            ".DS_Store",
            "._*",
            ".Spotlight-V100",
            ".Trashes",
            ".fseventsd",
            ".Trash-*",
            "(?i)Thumbs.db",
            "(?i)desktop.ini",
            "(?i)$RECYCLE.BIN",
            "(?i)System Volume Information",
            "(?i)hiberfil.sys",
            "(?i)pagefile.sys",
            "(?i)swapfile.sys",
            "@eaDir",
            "#recycle",
            ".zfs",
        ],
    ),
];

/// Written to DATA_DIR/excludes.txt the first time the client starts, so
/// the file is there to edit next to the rest of the config.
const TEMPLATE: &str = "\
// Files and folders in your backup folder that are never backed up.
// One pattern per line, same rules as Syncthing's .stignore:
//
//   *.iso              any .iso file, in any folder
//   /Downloads         the Downloads folder at the top of your backup folder only
//   node_modules       every folder named node_modules (and everything in it)
//   Photos/**/*.tmp    .tmp files anywhere under Photos
//   (?i)*.mkv          case-insensitive: also matches .MKV
//   !*.pst             back up .pst files after all (overrides the built-in list)
//
// `*` doesn't cross folders, `**` does. The first line that matches a file
// decides, so put `!` lines above the patterns they make exceptions to.
// Changes apply on the next check, no restart needed.
//
// A built-in list of poor fits is applied after this file: Outlook PST/OST,
// live database files (*.db, *.sqlite, ...), virtual machine disks
// (*.vmdk, *.vhdx, *.qcow2, ...), temp files and OS clutter. The client's
// README has the full list. Bring one back with a `!` line here, or turn
// the whole list off with DEFAULT_EXCLUDES=off in .env.
//
// Excluding something that's already backed up removes it from your
// buddy the same way deleting it would: they keep the last copy for 30
// days, then it's gone.
";

/// The file Rules::load reads; None (tests, the restore command) means
/// built-in defaults only.
static PATH: OnceLock<PathBuf> = OnceLock::new();

/// Text of the last exclude file loaded, so a change is logged once rather
/// than every cycle for every buddy.
static LAST_LOADED: Mutex<Option<String>> = Mutex::new(None);

/// Points the exclude list at `DATA_DIR/excludes.txt`, writing the
/// commented template there if it doesn't exist yet. Call once at startup.
pub async fn init(data_dir: &Path) {
    let path = data_dir.join(FILE_NAME);
    if tokio::fs::metadata(&path).await.is_err()
        && let Err(err) = tokio::fs::write(&path, TEMPLATE).await
    {
        tracing::warn!(path = %path.display(), ?err, "couldn't create the exclude list template");
    }
    let _ = PATH.set(path);
}

/// DEFAULT_EXCLUDES=off (or false/0/no) drops the built-in list.
fn defaults_enabled() -> bool {
    !matches!(
        std::env::var("DEFAULT_EXCLUDES").map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Ok("off" | "false" | "0" | "no")
    )
}

/// A compiled exclude list. Each pattern becomes a few globs (see
/// add_pattern); `owner` maps a glob back to its pattern so the first
/// matching *pattern* can win.
pub struct Rules {
    set: GlobSet,
    owner: Vec<usize>,
    exclude: Vec<bool>,
    has_negation: bool,
}

impl Rules {
    /// The person's list (if any) followed by the defaults (if enabled).
    /// An invalid line is an error rather than skipped: a skipped `!` line
    /// would silently exclude (and so remove from the buddy) files the
    /// person meant to keep.
    pub fn load() -> Result<Self> {
        let user_text = match PATH.get() {
            Some(path) => match std::fs::read_to_string(path) {
                Ok(text) => Some(text),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => return Err(err).with_context(|| format!("can't read {}", path.display())),
            },
            None => None,
        };
        let with_defaults = defaults_enabled();
        let rules = Self::build(user_text.as_deref().unwrap_or(""), with_defaults)
            .with_context(|| format!("in DATA_DIR/{FILE_NAME} (the config folder next to .env)"))?;

        let mut last = LAST_LOADED.lock().unwrap();
        let key = format!("{with_defaults}\n{}", user_text.as_deref().unwrap_or(""));
        if last.as_deref() != Some(key.as_str()) {
            tracing::info!(
                patterns = rules.exclude.len(),
                defaults = with_defaults,
                "exclude list loaded"
            );
            *last = Some(key);
        }
        Ok(rules)
    }

    pub fn build(user_text: &str, with_defaults: bool) -> Result<Self> {
        let mut b = Builder::new();
        for (n, line) in user_text.lines().enumerate() {
            b.add_line(line).with_context(|| format!("line {}: {:?}", n + 1, line.trim()))?;
        }
        if with_defaults {
            for (_, patterns) in DEFAULTS {
                for p in *patterns {
                    b.add_line(p).expect("built-in exclude patterns are valid");
                }
            }
        }
        Ok(Rules {
            set: b.set.build().context("can't compile the exclude list")?,
            owner: b.owner,
            exclude: b.exclude,
            has_negation: b.has_negation,
        })
    }

    /// Whether `rel_path` (relative to BACKUP_DIR, `/`-separated) is
    /// excluded, itself or through a folder it's in.
    pub fn is_excluded(&self, rel_path: &str) -> bool {
        self.set
            .matches(rel_path)
            .into_iter()
            .map(|glob| self.owner[glob])
            .min()
            .is_some_and(|pattern| self.exclude[pattern])
    }

    /// Whether an excluded folder can be skipped without looking inside.
    /// Not when there are `!` lines, since one might bring back a file in
    /// it (Syncthing makes the same call).
    pub fn can_skip_folders(&self) -> bool {
        !self.has_negation
    }
}

struct Builder {
    set: GlobSetBuilder,
    owner: Vec<usize>,
    exclude: Vec<bool>,
    has_negation: bool,
}

impl Builder {
    fn new() -> Self {
        Builder { set: GlobSetBuilder::new(), owner: Vec::new(), exclude: Vec::new(), has_negation: false }
    }

    fn add_line(&mut self, line: &str) -> Result<()> {
        let line = line.trim();
        if line.is_empty() || line == "#" || line.starts_with("//") || line.starts_with("# ") {
            return Ok(());
        }
        if line.starts_with("#include") {
            anyhow::bail!("#include isn't supported; put the patterns in this file");
        }
        let mut pattern = line;
        let mut exclude = true;
        let mut case_insensitive = false;
        loop {
            if let Some(rest) = pattern.strip_prefix('!') {
                exclude = false;
                pattern = rest;
            } else if let Some(rest) = pattern.strip_prefix("(?i)") {
                case_insensitive = true;
                pattern = rest;
            } else if let Some(rest) = pattern.strip_prefix("(?d)") {
                // Syncthing's "may delete" flag; nothing to do here.
                pattern = rest;
            } else {
                break;
            }
        }
        let anchored = pattern.starts_with('/');
        let pattern = pattern.trim_matches('/');
        if pattern.is_empty() {
            anyhow::bail!("empty pattern");
        }
        // The pattern itself, plus `/**` so a matching folder takes its
        // contents with it; unanchored ones may also start in any folder
        // (`**/` matches zero or more folders, so that covers the top too).
        let globs = if anchored {
            [pattern.to_string(), format!("{pattern}/**")]
        } else {
            [format!("**/{pattern}"), format!("**/{pattern}/**")]
        };
        let index = self.exclude.len();
        for glob in globs {
            let glob = GlobBuilder::new(&glob)
                .literal_separator(true)
                .case_insensitive(case_insensitive)
                .backslash_escape(true)
                .build()?;
            self.set.add(glob);
            self.owner.push(index);
        }
        self.exclude.push(exclude);
        self.has_negation |= !exclude;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(text: &str) -> Rules {
        Rules::build(text, false).unwrap()
    }

    #[test]
    fn syncthing_style_matching() {
        let r = rules("*.iso\n/Downloads\nnode_modules\nPhotos/**/*.tmp\n// comment\n# comment\n");
        assert!(r.is_excluded("a.iso"));
        assert!(r.is_excluded("deep/down/a.iso"));
        assert!(!r.is_excluded("a.iso.txt"));
        assert!(r.is_excluded("Downloads"));
        assert!(r.is_excluded("Downloads/x/y.jpg"));
        assert!(!r.is_excluded("old/Downloads/y.jpg"), "a leading / ties it to the top");
        assert!(r.is_excluded("code/app/node_modules/pkg/index.js"));
        assert!(r.is_excluded("Photos/2024/june/a.tmp"));
        assert!(r.is_excluded("Photos/a.tmp"));
        assert!(!r.is_excluded("Other/a.tmp"));
        assert!(!r.is_excluded("Photos/a.jpg"));
    }

    #[test]
    fn star_stays_within_a_folder() {
        let r = rules("/docs/*.txt");
        assert!(r.is_excluded("docs/a.txt"));
        assert!(!r.is_excluded("docs/sub/a.txt"));
    }

    #[test]
    fn case_only_ignored_when_asked() {
        let r = rules("*.mkv\n(?i)*.pst");
        assert!(!r.is_excluded("film.MKV"));
        assert!(r.is_excluded("mail/Archive.PST"));
    }

    #[test]
    fn first_match_wins() {
        let r = rules("!keep.pst\n*.pst");
        assert!(!r.is_excluded("mail/keep.pst"));
        assert!(r.is_excluded("mail/other.pst"));
        assert!(!r.can_skip_folders());

        // The other way round the `!` line never gets a say.
        let r = rules("*.pst\n!keep.pst");
        assert!(r.is_excluded("keep.pst"));
    }

    #[test]
    fn user_lines_override_defaults() {
        let r = Rules::build("!*.pst", true).unwrap();
        assert!(!r.is_excluded("Outlook/archive.pst"));
        assert!(r.is_excluded("Outlook/archive.OST"));
        assert!(r.is_excluded("vms/win11.vhdx"));
        assert!(r.is_excluded("app/data.sqlite"));
        assert!(r.is_excluded("Photos/Thumbs.db"));
        assert!(r.is_excluded("share/@eaDir/photo.jpg/SYNOPHOTO_THUMB_M.jpg"));
        assert!(r.is_excluded("share/#recycle/old.docx"));
        assert!(r.is_excluded("Documents/~$report.docx"));
        assert!(!r.is_excluded("Documents/report.docx"));
        assert!(!r.is_excluded("exports/vm-2026-10-01.xva"));
        assert!(!r.is_excluded("Photos/2024/IMG_0001.jpg"));
    }

    #[test]
    fn defaults_can_be_turned_off() {
        let r = Rules::build("", false).unwrap();
        assert!(!r.is_excluded("Outlook/archive.pst"));
    }

    #[test]
    fn bad_lines_are_errors_not_skipped() {
        let err = Rules::build("*.iso\n[unclosed\n", false).err().unwrap();
        assert!(format!("{err:#}").contains("line 2"), "{err:#}");
        assert!(Rules::build("!", false).is_err());
    }

    #[test]
    fn template_is_all_comments() {
        let r = Rules::build(TEMPLATE, false).unwrap();
        assert!(r.exclude.is_empty());
    }
}
