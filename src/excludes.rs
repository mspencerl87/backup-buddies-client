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
//! back any one default, and `DEFAULT_EXCLUDES=off` drops them all. The
//! built-in list is also written, as comments, at the bottom of that file
//! (see with_builtin_list), so people can see what they'd be overriding.
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
/// the file is there to edit next to the rest of the config. The built-in
/// list is appended below it by with_builtin_list.
const TEMPLATE: &str = "\
// Files and folders in your backup folder that are never backed up.
// One pattern per line, same rules as Syncthing's .stignore:
//
//   *.iso              any .iso file, in any folder
//   /Downloads         the Downloads folder at the top of your backup folder only
//   node_modules       every folder named node_modules (and everything in it)
//   Photos/**/*.tmp    .tmp files anywhere under Photos
//   (?i)*.mkv          case-insensitive: also matches .MKV
//   !(?i)*.pst         back up .pst files after all (overrides the built-in list)
//
// `*` doesn't cross folders, `**` does. The first line that matches a file
// decides, so put `!` lines above the patterns they make exceptions to.
// Changes apply on the next check, no restart needed.
//
// Excluding something that's already backed up removes it from your
// buddy the same way deleting it would: they keep the last copy for 30
// days, then it's gone.
//
// Add your own patterns here, above the built-in list.

";

/// Start of the part of excludes.txt the client owns. Everything from this
/// line down is regenerated at startup from DEFAULTS, so the list people
/// read is always the one actually applied, even after an update changes
/// it (a copy written once would go stale).
const BUILTIN_MARKER: &str =
    "// ===== Built-in list: rewritten by the client at every start, edit above this line =====";

/// `existing` (the file as it is, if any) with the built-in list section
/// replaced by the current one. Lines above the marker are kept as they
/// are; a file from before the marker existed keeps all of its lines.
fn with_builtin_list(existing: Option<&str>, enabled: bool) -> String {
    let own = match existing {
        Some(text) => match text.find(BUILTIN_MARKER) {
            Some(at) => &text[..at],
            None => text,
        },
        None => TEMPLATE,
    };
    let mut out = own.trim_end().to_string();
    out.push_str("\n\n");
    out.push_str(BUILTIN_MARKER);
    out.push('\n');
    out.push_str(if enabled {
        "//\n\
         // Poor fits for an off-site backup, skipped after the lines above are\n\
         // checked. They're comments here: the client applies them on its own. To\n\
         // back one up anyway, copy its line above the marker with `!` in front\n\
         // (e.g. `!(?i)*.pst`), or set DEFAULT_EXCLUDES=off in .env to back up all\n\
         // of them. `(?i)` means any case: .PST as well as .pst.\n"
    } else {
        "//\n\
         // DEFAULT_EXCLUDES=off is set in .env, so none of these are skipped right\n\
         // now. Shown for reference; remove that setting to skip them again.\n"
    });
    for (why, patterns) in DEFAULTS {
        out.push_str("//\n// ");
        out.push_str(why);
        out.push('\n');
        for p in *patterns {
            out.push_str("//   ");
            out.push_str(p);
            out.push('\n');
        }
    }
    out
}

/// The file Rules::load reads; None (tests, the restore command) means
/// built-in defaults only.
static PATH: OnceLock<PathBuf> = OnceLock::new();

/// Text of the last exclude file loaded, so a change is logged once rather
/// than every cycle for every buddy.
static LAST_LOADED: Mutex<Option<String>> = Mutex::new(None);

/// Points the exclude list at `DATA_DIR/excludes.txt`: creates it from the
/// template if it doesn't exist yet, and brings its built-in list section
/// up to date. Call once at startup.
pub async fn init(data_dir: &Path) {
    let path = data_dir.join(FILE_NAME);
    let existing = match tokio::fs::read_to_string(&path).await {
        Ok(text) => Some(text),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            // Leave a file we can't read alone; Rules::load reports it.
            tracing::warn!(path = %path.display(), ?err, "can't read the exclude list");
            let _ = PATH.set(path);
            return;
        }
    };
    let updated = with_builtin_list(existing.as_deref(), defaults_enabled());
    if existing.as_deref() != Some(updated.as_str())
        && let Err(err) = tokio::fs::write(&path, &updated).await
    {
        tracing::warn!(path = %path.display(), ?err, "couldn't update the exclude list file");
    }
    let _ = PATH.set(path);
}

/// The person's own part of excludes.txt (everything above the built-in
/// list), for the dashboard's editor.
pub async fn read_own() -> Result<String> {
    let path = PATH.get().context("the exclude list isn't set up")?;
    let text = match tokio::fs::read_to_string(path).await {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => TEMPLATE.to_string(),
        Err(err) => return Err(err).with_context(|| format!("can't read {}", path.display())),
    };
    let own = match text.find(BUILTIN_MARKER) {
        Some(at) => &text[..at],
        None => &text,
    };
    Ok(own.trim_end().to_string() + "\n")
}

/// Replaces the person's own part of excludes.txt with `own`, after
/// checking it compiles (so the dashboard can show the bad line instead of
/// the next backup cycle failing on it). Written to a temporary file and
/// renamed, so a backup cycle never reads half of it.
pub async fn save_own(own: &str) -> Result<()> {
    let path = PATH.get().context("the exclude list isn't set up")?;
    let own = match own.find(BUILTIN_MARKER) {
        Some(at) => &own[..at],
        None => own,
    };
    // Browsers send textarea contents with CRLF line endings.
    let own = own.replace("\r\n", "\n");
    Rules::build(&own, defaults_enabled())?;
    let text = with_builtin_list(Some(&own), defaults_enabled());
    let tmp = path.with_extension("txt.saving");
    tokio::fs::write(&tmp, &text).await.with_context(|| format!("can't write {}", tmp.display()))?;
    tokio::fs::rename(&tmp, path).await.with_context(|| format!("can't replace {}", path.display()))?;
    tracing::info!("exclude list changed from the dashboard");
    Ok(())
}

/// `rel_path` as a pattern that matches just that one file: tied to the top
/// of BACKUP_DIR, with glob characters escaped.
fn exact_pattern(rel_path: &str) -> String {
    let mut out = String::from("/");
    for c in rel_path.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '{' | '}' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// `own` with an exclude for exactly `rel_path` added. It goes above the
/// first pattern line (after the leading comments), so no `!` line can
/// bring the file back: the first match wins.
fn with_exact_exclude(own: &str, rel_path: &str) -> String {
    let pattern = exact_pattern(rel_path);
    let lines: Vec<&str> = own.lines().collect();
    if lines.iter().any(|l| l.trim() == pattern) {
        return own.to_string();
    }
    let at = lines
        .iter()
        .position(|l| {
            let l = l.trim();
            !(l.is_empty() || l == "#" || l.starts_with("//") || l.starts_with("# "))
        })
        .unwrap_or(lines.len());
    let mut out: Vec<String> = lines[..at].iter().map(|l| l.to_string()).collect();
    out.push("// Kept re-sending (excluded from the dashboard):".to_string());
    out.push(pattern);
    if at < lines.len() {
        out.push(String::new());
    }
    out.extend(lines[at..].iter().map(|l| l.to_string()));
    out.join("\n") + "\n"
}

/// Excludes exactly `rel_path` — the dashboard's one-click exclude for a
/// file that keeps re-sending.
pub async fn exclude_path(rel_path: &str) -> Result<()> {
    let own = read_own().await?;
    let updated = with_exact_exclude(&own, rel_path);
    if !Rules::build(&updated, defaults_enabled())?.is_excluded(rel_path) {
        anyhow::bail!("couldn't write a pattern that matches {rel_path:?}");
    }
    save_own(&updated).await
}

/// DEFAULT_EXCLUDES=off (or false/0/no) drops the built-in list.
pub fn defaults_enabled() -> bool {
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
        let r = Rules::build("!(?i)*.pst", true).unwrap();
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
    fn new_file_is_all_comments_and_lists_every_default() {
        let text = with_builtin_list(None, true);
        assert!(Rules::build(&text, false).unwrap().exclude.is_empty());
        for (_, patterns) in DEFAULTS {
            for p in *patterns {
                assert!(text.contains(&format!("//   {p}\n")), "{p} missing");
            }
        }
    }

    #[test]
    fn builtin_section_is_refreshed_and_own_lines_kept() {
        let mine = "// my list\n*.iso\n!(?i)*.pst\n";
        let first = with_builtin_list(Some(mine), true);
        assert!(first.starts_with(mine));
        // Unchanged on the next start, so the file isn't rewritten.
        assert_eq!(with_builtin_list(Some(&first), true), first);

        // A stale section (older client, or edited by hand) is replaced.
        let stale = format!("{mine}\n{BUILTIN_MARKER}\n//   *.old\n*.oops\n");
        let fresh = with_builtin_list(Some(&stale), true);
        assert_eq!(fresh, first);

        let r = Rules::build(&fresh, true).unwrap();
        assert!(r.is_excluded("a.iso"));
        assert!(!r.is_excluded("Mail/ARCHIVE.PST"));
        assert!(r.is_excluded("Mail/ARCHIVE.OST"));
    }

    // The only test that sets PATH (it's set once per process).
    #[tokio::test]
    async fn dashboard_edits_keep_the_builtin_section() {
        let dir = std::env::temp_dir().join(format!("bb-test-excludes-file-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        init(&dir).await;
        assert!(read_own().await.unwrap().starts_with("// Files and folders"));

        save_own("*.iso\r\n!(?i)*.pst\r\n").await.unwrap();
        let text = std::fs::read_to_string(dir.join(FILE_NAME)).unwrap();
        assert!(text.starts_with(&format!("*.iso\n!(?i)*.pst\n\n{BUILTIN_MARKER}\n")), "{text}");
        assert_eq!(read_own().await.unwrap(), "*.iso\n!(?i)*.pst\n");

        assert!(save_own("[oops").await.is_err());
        assert_eq!(std::fs::read_to_string(dir.join(FILE_NAME)).unwrap(), text, "a bad save changes nothing");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn exact_exclude_goes_above_the_first_pattern() {
        let own = "// my list\n\n!(?i)*.qcow2\n*.iso\n";
        let updated = with_exact_exclude(own, "vm/big disk [old].qcow2");
        assert!(updated.starts_with("// my list\n\n// Kept re-sending"), "{updated}");
        let r = Rules::build(&updated, true).unwrap();
        assert!(r.is_excluded("vm/big disk [old].qcow2"), "beats the earlier `!` line");
        assert!(!r.is_excluded("vm/other.qcow2"));
        assert!(!r.is_excluded("other/vm/big disk [old].qcow2"), "only that one path");
        assert_eq!(with_exact_exclude(&updated, "vm/big disk [old].qcow2"), updated, "added once");

        // Only comments (a fresh file): it goes at the end.
        let fresh = with_exact_exclude(TEMPLATE, "a.db");
        assert!(fresh.ends_with("// Kept re-sending (excluded from the dashboard):\n/a.db\n"), "{fresh}");
    }

    #[test]
    fn builtin_section_says_when_defaults_are_off() {
        let text = with_builtin_list(None, false);
        assert!(text.contains("DEFAULT_EXCLUDES=off is set"));
    }
}
