# Backup Buddies client

The agent that actually talks to your buddy's machine over Iroh (P2P,
NAT-traversal via `relay.filegarden.net` when a direct connection isn't
possible) and exchanges backup data. Everything up to this point — the
website, your account, billing, pairing with a buddy — is just
bookkeeping; this is the piece that does the real work.

**Current status:** real backup and restore. Every 30 seconds (or
`SCAN_INTERVAL_SECS`) it asks the
API who your paired buddies' devices are, then — if this device has
`BACKUP_DIR` set (which `docker-compose.yml` always does; it just points
at an empty, read-only folder when you haven't set `BACKUP_DIR_HOST`) —
scans that folder (skipping anything on the exclude list, see "Excluding
files") and, when anything changed, saves a new snapshot of it to an
encrypted repository on each buddy's device, sending only the chunks the
buddy doesn't have yet (see "How backups are stored"). A deleted file is
left out of the next snapshot, and older snapshots keep it for 30 days.
A receive-only device (no `BACKUP_DIR_HOST`
set) still runs this same cycle against its empty folder every 30
seconds — you'll see "nothing new to back up" instead of "backup cycle
complete" every time, not a separate connectivity-only message, so "is
this still working" never depends on actually having something to send.

## What it does and doesn't do

- **Does:** generate and persist a unique Iroh identity for this device,
  register it with your account, discover your buddy's device, connect to
  it (directly if possible, through the relay otherwise), and encrypt
  everything with `BACKUP_PASSPHRASE` *before* it ever leaves this
  machine.
- **Does:** send only what changed. A cycle lists the folder (metadata
  only); an unchanged folder costs that listing and nothing else. When
  something changed, only the chunks your buddy doesn't already have are
  sent: a renamed or moved file costs next to nothing, and an edit to a big
  file costs about the part that changed.
- **Does:** keep earlier versions. Every backup with a change is a
  snapshot, kept every one for a day, hourly for two days and daily for 30
  days, browsable and restorable from the local dashboard (see "File
  versions" below).
- **Does not:** send your passphrase anywhere. It's used locally to
  derive an encryption key and never appears in any API call, log line,
  or network request. If you lose it, data stored with your buddy cannot
  be recovered — there's no "forgot passphrase" flow, by design.
- **Does not:** let your buddy read your data. Their client stores
  whatever bytes you send it verbatim, without trying to decrypt them —
  and only ever lets *you* list or fetch back what *you* stored with
  them, never another buddy's data. They see only encrypted pack files:
  not your file or folder names, how many files you have, or their sizes
  (see "How backups are stored").

## What to back up (and what not to)

Backup Buddies is for keeping an **off-site copy** of files you'd hate to
lose, on a buddy's machine somewhere else, so one dead disk, theft or
house fire doesn't take your only copy. It works best with files that are
written once or change now and then.

**Good fits:** photos and videos, music, scans and paperwork, documents,
finished projects, and exports made by other tools (VM backup files,
database dumps, phone or app backups). Each export is a new, finished
file, which is what this handles best.

**Poor fits, and why:**

- **Running VM disks and live databases.** They change while being read,
  so the copy your buddy holds may not open or boot on restore. Back up
  the VM's or database's own export or snapshot instead.
- **Big files that change all the time** (Outlook PST files, photo
  catalogs, encrypted containers). Only the parts that changed are sent,
  but a file that's largely rewritten every day still adds up: an
  encrypted container changes throughout, so a 20 GB one used daily is
  sent nearly in full each time, around 600 GB a month over both your
  connections. If it goes through the relay, that counts toward the free
  monthly relay allowance (syncing pauses past it until the 1st) or is
  billed per GB on a paid plan. Fine if they rarely change.
- **Things you can get back anyway:** caches, temp files, downloads,
  games, OS and program folders. They just use up your buddy's pledge.
- **Keeping your own devices in sync.** This is a one-way backup to
  someone else's machine, checked every `SCAN_INTERVAL_SECS` (30 s by
  default), and restoring is deliberate. Use a sync tool like Syncthing
  for that.
- **Your only copy of something.** This is the second copy. Your buddy's
  machine can be off, their disk can fail, and they can leave. Keep the
  originals.

The client skips the worst of these by default and lets you exclude
anything else (see "Excluding files" below).

## How backups are stored

Each buddy keeps a restic-format repository (built with rustic_core) under
`<your node id>/.repo/` in their buddy files. Files are split into chunks
by their content, so:

- renaming or moving a file or folder sends next to nothing (in testing,
  renaming a 1 GB file and moving 300 photos stored 0 bytes);
- editing part of a big file sends only the chunks it touched (1 MB
  changed in the middle of a 1 GB file: about 1–6 MB);
- identical content is stored once, wherever it appears.

Chunks are encrypted (AES-256-CTR with Poly1305-AES) and packed into
~32 MB pack files, each named by its SHA-256, which the buddy checks as it
arrives. Each cycle that finds a change saves a snapshot. Snapshots are
kept every one for 24 hours, then one per hour up to 2 days, then one per
day up to 30 days; once a day older ones are forgotten and their space
freed (prune).

**What your buddy sees:** the pack files, how big each one is (so roughly
how big your backup is) and when they change. Not your file or folder
names, how many files you have, their sizes, or anything inside them.

**The key** comes from your passphrase: it goes through scrypt once at
startup (`log_n=18, r=8`, ~1 s and 256 MB), salted with your account id,
and the repository's master key is a labelled hash of the result. So the
passphrase and a device token on the same account restore everything on
a rebuilt device, no key file is ever written, and the same passphrase
gives a different key on every account. Passphrase length still matters
(the client warns under 12 characters).

A backup's threads run on at most 4 CPUs, since rustic_core sizes its
thread pools to the CPUs it can see (a backup peaked at ~560 MB on 16
CPUs and ~250 MB on 2 in testing).

Buddies need client 0.16.0 or later to store a repository. Client 0.21.0
dropped the whole-file backups older clients made: a buddy on a client
before 0.16.0 fails each cycle with "your buddy's client is too old" until
they update.

## Excluding files (0.10.0)

Everything in `BACKUP_DIR_HOST` is backed up except what the exclude list
says. It works like Syncthing's `.stignore`, with two parts:

**Built-in list.** Poor fits are skipped without you doing anything:

| What | Patterns |
|---|---|
| Outlook mail stores | `*.pst`, `*.ost` |
| Live databases and their journals | `*.db`, `*.db-wal`, `*.db-shm`, `*.db-journal`, `*.sqlite`, `*.sqlite3`, `*.sqlite-wal`, `*.sqlite-shm`, `*.sqlite-journal`, `*.mdf`, `*.ndf`, `*.ldf`, `*.ibd`, `*.ldb`, `*.laccdb` |
| Virtual machine disks, checkpoints and memory | `*.vmdk`, `*.vhd`, `*.vhdx`, `*.avhd`, `*.avhdx`, `*.vdi`, `*.qcow`, `*.qcow2`, `*.hds`, `*.vmem`, `*.vmsn`, `*.vmss`, `*.vmrs` |
| Temporary, lock and half-downloaded files | `*.tmp`, `~$*`, `.~lock.*#`, `*.swp`, `*.part`, `*.partial`, `*.crdownload` |
| System files, trash and snapshot folders | `.DS_Store`, `._*`, `.Spotlight-V100`, `.Trashes`, `.fseventsd`, `.Trash-*`, `Thumbs.db`, `desktop.ini`, `$RECYCLE.BIN`, `System Volume Information`, `hiberfil.sys`, `pagefile.sys`, `swapfile.sys`, `@eaDir`, `#recycle`, `.zfs` |

Extensions are matched in any case (`.PST` too). Exports and finished
files are deliberately *not* on the list: `.xva`, `.ova`, `.iso`, database
dumps (`.sql`, `.bak`), Lightroom catalogs, encrypted containers and
Access databases are all still backed up. `DEFAULT_EXCLUDES=off` in
`.env` turns the built-in list off. To back up just one of these, copy its
line from the bottom of `excludes.txt` above the marker with `!` in front,
e.g. `!(?i)*.pst` (`(?i)` makes it match any case, like the built-in one).

**Your own list** is `excludes.txt` in the config folder
(`DATA_DIR_HOST`, `./config` by default). The client creates it, with
examples, the first time it starts. At the bottom it lists the built-in
patterns as comments, under a marker line; the client rewrites that part at
every start so it always matches what's applied, and never touches the lines
above it. Add your patterns above the marker, one per line:

| Pattern | Excludes |
|---|---|
| `*.iso` | any `.iso` file, in any folder |
| `/Downloads` | the `Downloads` folder at the top of your backup folder only (and everything in it) |
| `node_modules` | every folder named `node_modules`, at any depth |
| `Photos/**/*.tmp` | `.tmp` files anywhere under `Photos` |
| `(?i)*.mkv` | `.mkv` in any case (patterns are case-sensitive otherwise) |
| `!(?i)*.pst` | nothing: it **brings back** `.pst` files (any case) the built-in list would skip |

`*` matches within one folder, `**` across folders; `?`, `[a-z]` and
`{jpg,png}` work too. Lines starting with `//` (or `# `) are comments. The
**first** line that matches a file decides, and your list is checked
before the built-in one, so a `!` line goes above whatever it makes an
exception to. Edits apply on the next check; no restart needed. A line the
client can't understand stops backups with an error naming the line,
rather than being skipped. The dashboard shows how many files (and
skipped folders) were excluded under **Local files**.

The dashboard's **Exclusions** card (0.11.0) edits the same file: it shows
your lines, with the built-in list underneath, and checks a change before
saving it, so a bad line is shown to you instead of stopping the next
backup. Editing the file directly still works too.

**Excluding something that's already backed up works like deleting it**:
it's left out of the next snapshot, and older snapshots keep it for 30
days (see "File versions"). If your list would exclude everything while
your last snapshot had files, the client stops and says so instead of
saving an empty snapshot.

## Running it

If you don't already have this directory (e.g. you don't have access to
the project's private source repo), get it with:

```bash
curl -fsSL https://app.filegarden.net/client/install.sh | bash
cd backup-buddies-client
```

Then fill in `.env` — a device token from your dashboard's Devices card,
your own passphrase, the folder you want backed up (`BACKUP_DIR_HOST`,
optional — leave it unset if this device is only meant to receive), and
the API URL (you can usually leave that last one as-is) — and:

```bash
docker compose up -d
docker compose logs -f
```

You should see a line confirming your device registered with the API.
Once your buddy's client is also running (and your pairing is active),
you'll see a cycle line roughly every 30 seconds: "backup cycle complete"
if there was something to send, or "nothing new to back up" if not
(which is what you'll see every time if you haven't set
`BACKUP_DIR_HOST`) — either way, it confirms the connection is working.

Before any of that, the client checks its own setup and refuses to start
with a clear error rather than failing confusingly later — a `BACKUP_DIR`
that doesn't exist, a `DATA_DIR` it can't actually write to, or an
`API_URL` that isn't a valid URL all stop it immediately. A short
`BACKUP_PASSPHRASE` (under 12 characters) doesn't stop it, but logs a
warning — there's no way to recover your data if it's ever lost or
guessed, so a short one is worth reconsidering.

## Status dashboard

This device also serves its own small status page — not to be confused
with your account dashboard on the website — at
**http://&lt;this machine's address&gt;:8080** (or whatever `DASHBOARD_PORT`
you set), once `docker compose up -d` is running. It shows, per buddy:
their pledge to you and how much of it is used, how many files (and how
much) your last snapshot on their side holds, the size of the backup they
keep with you, and the result of the last backup cycle (or ping, for a
buddy you're not backing anything up to).
There's also a "Restore from this buddy" button, which does the same
thing as the `restore` command below and writes to the same place
(`RESTORE_DIR_HOST/<their node id>/`), showing you the result right there
instead of needing a terminal.

It also has: a file browser with older versions of each file, an
**Activity** log of what happened (see below), the **Exclusions** editor
(see "Excluding files"), and the device's disk and bandwidth. It's behind a login set in `.env` (see
"Logging in").

### Activity (0.13.0)

Under the buddy cards, **Activity** lists the last 50 things that happened,
newest first, in plain language: files backed up to or removed from a
buddy's snapshot (click a line for the file list), a buddy becoming
unreachable or failing (a full pledge, say) and working again, what a
buddy stored with you, pruned or read back, restores you ran, exclude-list changes, logins (and
wrong passwords, with the address), password changes, startups and
available updates. The chips filter it to Backups, Problems or Security.

Routine checks that find nothing new, and pings, aren't listed (they run
every 30 seconds and the buddy cards already show them). A buddy that stays
broken is one line when it breaks and one when it recovers. Events are kept
for 30 days (at most 1,000) in the index, so they survive a restart.

**Raw log** shows the last 300 lines of the client's own log, the same as
`docker compose logs`, for when the plain-language list isn't enough. Those
are kept in memory only and start over when the client restarts.

### Logging in (0.11.0)

The dashboard can restore your decrypted files and change what's backed up,
so every page asks for a login, from any device:

1. **First time:** put a password in `.env` and restart
   (`docker compose up -d`):
   ```
   DASHBOARD_PASSWORD=choose-a-long-one
   ```
   Log in as `admin` (or set `DASHBOARD_USER` too).
2. **Change it** whenever you like with **Change password** at the top of the
   dashboard. The new one is stored, hashed, in the config folder
   (`dashboard-login`) and replaces the `.env` password from then on.
3. **Forgot it?** Delete `dashboard-login` from the config folder and
   restart; the password in `.env` works again.

You stay logged in for 30 days, or until the client restarts. Five wrong
passwords in a row from one address lock it out for a minute. Changing the
password logs out every other browser. Without any password the dashboard
stays locked and says to set one: there's deliberately no default password,
since one that works until someone changes it works for whoever on your
network tries it first.

The login is plain HTTP like the rest of the dashboard: fine on your own
network, but if this machine is reachable from somewhere you don't trust
(the open internet, a guest network), reach it over an SSH tunnel or VPN,
or put a reverse proxy with HTTPS in front of it. The dashboard also
refuses changes posted from other websites (including other web apps on the
same machine), so a page you visit can't act on it through your browser.

## Restoring

To pull everything a buddy is holding for you back down and decrypt it:

```bash
docker compose run --rm client restore <buddy's node id>
```

Find the buddy's node id on your dashboard's Buddies card. Files land
under `<their node id>/` inside your `RESTORE_DIR_HOST` folder on the host
(pass a container path as a third argument to send them elsewhere),
decrypted with the `BACKUP_PASSPHRASE` in your `.env` — so this only
works from a machine configured with the *same* passphrase that encrypted
the data in the first place, and a `DEVICE_TOKEN` from the same account
(the key is salted with the account id, so a different account's token
derives a different key). This is a one-shot operation: the client
restores every file in the latest snapshot and exits, rather than running
as part of the normal daemon loop. Earlier versions, and deleted files,
restore from the dashboard's History.

## Building locally

```bash
cargo build --release
# or, to build the Docker image yourself instead of pulling it:
docker build -t backup-buddies-client .
```

## Verifying the image

The published image is built by GitHub Actions from the public repo,
github.com/mspencerl87/backup-buddies, and each build comes with a
provenance attestation: a statement, signed by GitHub for that workflow
run, that an image with this exact digest was built by
`.github/workflows/build-client.yml` from a given commit. Since 0.15.0 each
release is also tagged with its version. With the GitHub CLI:

```bash
gh attestation verify oci://ghcr.io/mspencerl87/backup-buddies/client:0.15.0 --repo mspencerl87/backup-buddies
```

A pass means the image was built by that repo's CI (not uploaded from
someone's machine), shows the commit it came from so you can read exactly
that code, and confirms the image hasn't changed since. It doesn't review
the code for you; it ties what you run to what's published. To check the
image you're actually running, use its digest
(`docker compose images`, or `docker inspect --format '{{index .RepoDigests 0}}' <image>`)
in place of the tag. Images built before this was added have no
attestation, including the very first 0.15.0 build; pulling again gets
the attested one.

## Updating, and releasing a new version

There are two ways people run the client, and one update command covers
both. Users run it from inside their client folder (the one with `.env`):

```bash
curl -fsSL https://app.filegarden.net/client/install.sh | bash -s -- --update
```

- **Image installs** (the setup page's two files: a `docker-compose.yml`
  running `ghcr.io/…/client:latest`, plus `.env`): runs
  `docker compose pull && docker compose up -d`. Nothing in the folder is
  changed; the compose file is the user's own. Setup-page users can also
  just run that pull command themselves.
- **Source installs** (made by `install.sh`, with `Cargo.toml` and `src/`):
  replaces only the code (`src/`, `assets/`, `Cargo.*`, `Dockerfile`,
  `docker-compose.yml`) and runs `docker compose up -d --build`.
  Everything is downloaded to a temp folder first, so a failed download
  leaves the old install untouched. A hand-edited `docker-compose.yml` is
  saved as `docker-compose.yml.bak`.

Neither path touches `.env` or the data folders. A folder that's neither
kind (no client `Cargo.toml`, and no uncommented `image:` line for the
client) is refused rather than guessed at.

The client sends `User-Agent: backup-buddies-client/<Cargo.toml version>` on
every API call. The API records it per device (`devices.client_version`),
and the web dashboard compares it to the version in `apps/client/Cargo.toml`
(served at `/client/Cargo.toml`). Any device on an older version, or one
that reports no version (anything before 0.2.0), gets an "update available"
badge with the command above.

Since 0.6.0 the client's own local dashboard does the same check: every
hour it reads that same `/client/Cargo.toml` (the `app.` sibling of
`API_URL`'s `api.` host, or `UPDATE_CHECK_URL`; `off` disables it) and the
"This Device" card shows "Up to date" or "Update available: x.y.z" with the
update command for that install kind (the CI-built image sets
`BB_INSTALL_KIND=image` and shows `docker compose pull && docker compose up -d`;
a local build shows the `install.sh --update` command). If the check can't complete (offline), nothing is shown
rather than a false "up to date". It deliberately doesn't use GitHub
releases: an `install.sh` build has no `.git` to read a commit from,
whereas every install knows its own version.

**So: bump `version` in `Cargo.toml` whenever you ship a client change users
should get**, and update `Cargo.lock` in the same commit. Running
`cargo build` once does that, or edit the `backup-buddies-client` entry by
hand. The Dockerfile builds with `--locked`, so a stale lock fails the build.
Without a bump, nobody is told to update. (For the hosted service, the
version devices compare against is served from app.filegarden.net, which
is updated as part of its own deploy.)

## Folders

The client uses four separate folders, each bind-mounted from the host
(see `.env.example`), so its own files never end up mixed into your data:

| Host setting | In the container | What's in it |
| --- | --- | --- |
| `DATA_DIR_HOST` (default `./config`) | `/data` (`DATA_DIR`) | The client's own config and state. Small. |
| `BACKUP_DIR_HOST` | `/backup` (read-only) | Your files. Only ever read. |
| `BUDDY_FILES_DIR_HOST` (default `./buddy-files`) | `/buddy-files` (`BUDDY_FILES_DIR`) | What buddies store with you. Uses the space you pledged. |
| `RESTORE_DIR_HOST` (default `./restored`) | `/restored` (`RESTORE_DIR`) | Files you restore from a buddy. |

`BUDDY_FILES_DIR` and `RESTORE_DIR` default to `DATA_DIR/received` and
`DATA_DIR/restored` when unset.

Config (`DATA_DIR`):

- `iroh_secret_key` — this device's identity. Deleting it means the
  device re-registers under a new identity next startup (update it on
  your dashboard, or just remove and re-add the device there).
- `chunked/` — per buddy, a fingerprint of the folder at the last
  snapshot (so an unchanged folder needs no connection) and when old
  snapshots were last pruned, plus rustic's cache of repository index and
  tree data. Deleting it means the next cycle reads every file once more,
  sending only what the buddy doesn't have; it doesn't affect what's
  stored on either side.
- `index.sqlite` (+ `-wal`/`-shm`) — the dashboard's Activity events
  (SQLite). Deleting it just empties the Activity card.
- `usage.json` — `{ "<buddy node id>": <bytes received from them> }`,
  tracked per buddy device and checked against their pledge
  (`buddy_pairings.pledged_bytes`, fetched from the API every 30s) before
  accepting any incoming file. The pledge is per account: since 0.15.1, a
  buddy running several devices shares one pledge across all of them,
  rather than each device getting the whole of it. Deleting it resets
  what's counted toward each buddy's pledge back to zero — the underlying buddy files are
  untouched, so this can desync the two if used carelessly.
- `bandwidth.json` — lifetime bytes moved via relay vs. direct (see
  "Relay bandwidth" below). Deleting it just resets the dashboard's
  counter back to zero.

Buddy files (`BUDDY_FILES_DIR`):

- `<buddy node id>/.repo/` — a buddy's backup: encrypted pack, index and
  snapshot files in the restic repository layout, named by their content
  hashes. It holds the whole backup, history included, and counts against
  that buddy's pledge in full. This device never attempts to decrypt it —
  it has no reason to ever hold the sender's passphrase. Don't edit or
  delete anything in it by hand; a missing pack loses whatever was in it.
- `<buddy node id>/.incoming/` — writes in progress, moved into `.repo/`
  once complete and checked; cleared at startup.

Anything else in a buddy's folder (whole files and `.versions/` from
clients before 0.21.0) isn't used or counted any more; delete it by hand.

A folder whose node id isn't one of your buddies' devices any more (their
client got a new identity, or the pairing ended) is removed 30 days after
this device first notices, unless that device comes back. Its card on the
dashboard says when. The dates are kept in `orphans.json` in the config
folder.

Restores (`RESTORE_DIR`): `<buddy node id>/...` — only appears after a
restore.

## Running as your own user (PUID/PGID)

Set `PUID`/`PGID` in `.env` (from `id -u` / `id -g`) and the container's
entrypoint (`docker-entrypoint.sh`) starts as root just long enough to hand
the client's own folders — config, buddy files, restores, never your
read-only backup folder — to that user, then runs the client as it via
`setpriv`. Restored files then belong to you, and buddy files can live on
an NFS share where root is squashed. The ownership fix only walks a folder
when something near its top (two levels) isn't owned yet, so restarts don't
stat every stored file. Unset, the client runs as root as before.

## Wrong-folder and missing-drive protection

- **Buddy files:** the first time a buddy-files folder is used, the client
  writes a random ID into `.backup-buddies-id` there and keeps a copy in
  `DATA_DIR/buddy-files-id`. If they don't match on a later start — most
  often a drive that wasn't mounted yet, so Docker bound the empty mount
  point — the client refuses to start rather than storing buddy files on
  the wrong disk. Deleting `buddy-files-id` deliberately starts over.
- **Your files:** if `BACKUP_DIR` scans completely but comes back empty
  while your last snapshot had files, the cycle fails with an explanation
  instead of saving an empty snapshot. `ALLOW_EMPTY_BACKUP_DIR=true`
  overrides it; remove it again afterwards (the client warns at startup
  while it's set).
- **Unreadable files or folders:** reported on the dashboard as files that
  can't be backed up, and left out of that snapshot; the rest is backed up
  as usual. Older snapshots keep what they had, for 30 days.

## Backup progress on the dashboard

While a backup cycle runs, each buddy card on the local dashboard shows a
progress bar: "checking" while the folder is scanned, then "backing up"
(bytes read of the folder's total, speed and time left). A backup reads
every file but sends only new chunks, so it's measured in bytes read. It
disappears when the cycle ends and the normal last-cycle line takes over.
Served as `in_progress` on each buddy in `/api/status`.

## Dropped connections

A connection that drops mid-backup is reopened and the call tried again,
up to 3 times, without starting the cycle over. If the backup still fails,
the next cycle (about 30 seconds later) runs it again. A refusal (pledge or
disk full) isn't retried; the cycle reports it.

## Known issue: dropped connections between two clients on one machine

With two clients on the same machine backing up to each other, a long
transfer occasionally loses its connection partway through, usually
minutes in, logged as
`failed closing path err=LastOpenPath` and then `connection lost` /
`timed out`. The client reconnects and carries on (above). Seen only with two clients on the same machine, where
every interface address, including the Docker bridge (`docker0`,
172.17.0.1), is offered as a route. Between two separate machines on one
local network, about 21 GB over three long transfers ran clean.

## Large folders and large files

- **Change detection:** each cycle lists the folder (paths, sizes and
  modified times only) and compares a fingerprint of that with the last
  snapshot's; when they match, nothing is read. The cycle still connects
  and checks the buddy lists the last snapshot saved there (that replaces
  the old connectivity ping); if it doesn't, because the buddy lost or
  deleted it, the next backup is a full one, and Activity says so.
  When they don't, rustic reads files whose size or modified time changed
  since the parent snapshot (inode and ctime are ignored, since they
  change across an SMB/NFS remount) and sends only new chunks.
  `SCAN_INTERVAL_SECS` (default 30, minimum 5) sets how often a cycle
  runs; staleness on the dashboard scales with it.
- **Memory:** bounded by rustic and the 4-CPU cap above, not by file
  size or count. Restores don't use rustic's own restore (it reads on many
  threads with no backpressure, and panics on a failed read): each file is
  read in 4 MiB pieces into a temporary file and moved into place once
  complete. Repository files land in a hidden `.incoming/` folder on the
  buddy's side and are moved into place only once complete and checked.
- **Large repositories:** the buddy lists repository files in chunks of
  5,000 (`RepoList`), so any number of packs and snapshots works.
- Tested end to end (`src/e2e_tests.rs`): two real endpoints over
  localhost, the real backup, receive and restore code.

## Disk safety: pledges vs. the real disk

A pledge is just a number two accounts agreed on over the API — it's not a
reservation the filesystem enforces. On top of the per-buddy pledge check
above, every incoming pack is also checked against the *real* free space on
the filesystem under `BUDDY_FILES_DIR` — where incoming files actually land,
which may be a different disk from `DATA_DIR` (`statvfs`, same mechanism the
dashboard's Disk card and the buddy disk-stats probe read). A write that would eat into a floor of whichever is
bigger — 2GB flat, or 5% of the filesystem's total size — is rejected with
"not enough disk space on this host", independent of whether the sender is
still within their pledge. This is what keeps an over-pledge (or anything
else filling the same disk) from being able to actually starve the host,
with no admin intervention needed.

The dashboard also lets you check a buddy's *real* numbers directly — each
buddy card fetches their live disk stats (total/free, and what they've
pledged out to everyone, not just you) over the sync protocol and shows it
next to their pledge, with a "Recheck" button for an on-demand refresh. If
a buddy's actual free space is less than what they've pledged out, it's
called out in red — useful for spotting a buddy who over-pledged before
anything actually fails.

## Network/transfer visibility

Each backup cycle and restore reads its own transfer numbers straight off
the connection: bytes actually sent/received (including protocol overhead,
not just file sizes — a more honest number) and wall-clock duration, shown
on the dashboard as a rate (e.g. "1.2 MB in 3.1s (390 KB/s)") next to that
buddy's last cycle and any restore result.

Also shown: whether the connection to a buddy ended up **direct**
(hole-punched peer-to-peer) or went **via relay**
(`relay.filegarden.net`), plus round-trip latency. iroh always tries direct
first and only falls back to the relay when NAT traversal doesn't work out
— a buddy stuck on relay will generally see lower throughput than a direct
one, so this is usually the first thing to check if someone's transfers
seem slow. All of this is local telemetry read off iroh's own connection
object (`Connection::paths()`/`Connection::stats()`) — none of it is sent
over the wire or costs an extra round trip.

A direct connection is only *possible* if something outside your network
can actually reach this device on its sync port — `SYNC_PORT` in
`.env` (11235 by default), published by `docker-compose.yml`. Forwarding
that same port on your router gives NAT traversal a real shot; without
it, every connection relays no matter how good either side's network
otherwise is, since nothing can ever reach this device from outside to
hole-punch with. Forwarding it is entirely optional — nothing breaks if
you skip it, transfers just relay instead, same as before this existed.
Note that two buddies behind the *same* NAT/public IP (e.g. both on the
same home network as this host) are a case port forwarding can't help —
most routers won't let a device reach another device behind the same NAT
via the NAT's own public address ("hairpinning"), regardless of what's
forwarded.

For buddies who genuinely are on the same local network — two NAS boxes
in the same house, say — the client also runs local discovery over mDNS
(same idea as Syncthing's LAN discovery): each client broadcasts/listens
on the LAN and, if it finds its buddy there, connects over the private
network directly. This sidesteps the relay and the router's NAT/hairpin
behavior entirely rather than trying to traverse it. Look for
`"found a buddy on the local network (mDNS)"` in the logs to confirm
it's working.

This needs `network_mode: host` in `docker-compose.yml` (already set by
default) — mDNS relies on real LAN multicast, which a normally-networked
(bridge-mode) container can't receive no matter what ports are
published, even to another container on the *same host*. Host networking
means the app's `DASHBOARD_PORT`/`SYNC_PORT` now bind directly on the
host rather than through a Docker port mapping, so **each device sharing
a host needs its own distinct values for both** — no longer just "if the
default's taken," but required. It's Linux-only; on Docker Desktop
(Mac/Windows), drop `network_mode: host` and publish ports the normal
way instead — everything still works, just without same-LAN direct
connections (relay and direct-over-internet are unaffected).

There's no live, mid-transfer rate (e.g. "currently uploading at 2MB/s") —
cycles run every 30s and are usually short, so a last-cycle average is
what's shown rather than adding a streaming/websocket layer for numbers
that would mostly read "idle" between cycles anyway.

Lifetime relay-vs-direct totals are also shown, in their own card on the
dashboard — see "Relay bandwidth" below, including how that figure now
actually is wired up to billing.

## File versions — protection against overwrites and accidental deletes

Every backup with a change is a snapshot, so a file you overwrite or
delete is still in the snapshots from before, which are kept every one for
24 hours, hourly for 2 days and daily for 30 days.

To get one back: open **Browse files** on a buddy's card. Deleted files
(and the old names of renamed ones) are listed too, marked "deleted —
recoverable". Click **History** next to a file and pick a version: each
distinct earlier content, newest first, with when it's removed. It's
written to `RESTORE_DIR/<buddy>/<path>.v<N>.bak` — alongside, never over, a
normal restore of that file — so you can compare before deciding what to
keep.

A file can't be cut out of existing snapshots, so its copies go when those
snapshots age out; there's no "delete permanently".

**What your buddy sees (0.15.0).** **Browse files** has a **What your
buddy sees** button that lists the pack files your backup is stored in, as
they sit on the buddy's disk, with their sizes. Click one to see its first
256 bytes exactly as stored, so you can check for yourself that nothing on
their side is readable.

## Buddy health — staleness and per-file failures

The pill next to each buddy's name shows the *last* cycle's result, but a
buddy could look fine on that alone while quietly failing for a while
(say, a one-off error that happens to land on the very last cycle you
happened to check). The dashboard tracks this separately: if a buddy
hasn't had a *successful* cycle in over `STALE_AFTER_SECS` (10 minutes by
default — see `.env.example`), a red **stale** badge shows up next to
their status, saying how long it's actually been since something last
went through.

Separately, if specific files can't be read while the cycle otherwise runs
fine, they're called out by name under that buddy's card (capped at the
first 10, if there are more) rather than just logged. A cycle with any
failing files isn't reported as fully "ok" either, for the same reason. A
buddy whose pledge or disk is full shows an amber "doesn't fit" instead of
a red failure: the last snapshot is still there.

## Relay bandwidth

Every file transferred — your own backups and restores, and anything a
buddy pushes to or pulls from you — is tallied by which network path
carried it, direct or via `relay.filegarden.net`, and kept as a running
lifetime total in a **Bandwidth** card on the dashboard (persisted to
`data/bandwidth.json`, so it survives restarts). Direct peer-to-peer
transfers don't touch the relay at all and are never billed; only the
relay figure is.

If your account has an active paid subscription, relay bandwidth is billed
separately from storage, at a rate shown on your dashboard's billing card
(whole-megabyte granularity — fractions of a megabyte just carry over to
the next report). Every ~30 seconds, alongside the existing buddy-list
poll, this client reports however many megabytes of relay traffic have
accumulated since its last successful report, and only then advances its
own internal "already reported" marker — so a failed poll re-reports the
same bytes next cycle instead of losing them, and nothing is ever reported
twice. Free-tier accounts are never billed for relay bandwidth. They get
a monthly relay allowance instead (shown on the billing card); past it,
buddy syncing pauses until the 1st of the next month, or until the
account subscribes.

## Commands and settings

Everything you can run or set, in one place. The sections above explain
the reasons behind most of it.

### Commands

Run these from the folder with your `docker-compose.yml` and `.env`.

| Command | What it does |
|---|---|
| `curl -fsSL https://app.filegarden.net/client/install.sh \| bash` | Fresh install: creates `./backup-buddies-client/` with the source, compose file and an `.env` to fill in. Doesn't start anything |
| `curl -fsSL https://app.filegarden.net/client/install.sh \| bash -s -- --update` | **`--update`**, the only flag the installer takes: updates an existing install in place, run from inside the install folder or the folder containing it. For image installs it pulls the latest image and restarts; for source installs it replaces only the code and rebuilds. It never touches `.env` or the data folders |
| `docker compose up -d` | Start (or apply `.env` changes) |
| `docker compose logs -f` | Follow the log (Ctrl+C to stop) |
| `docker compose down` | Stop |
| `docker compose pull && docker compose up -d` | Update an image install by hand |
| `gh attestation verify oci://ghcr.io/mspencerl87/backup-buddies/client:<version> --repo mspencerl87/backup-buddies` | Check an image was built by the public repo's CI, and from which commit (see "Verifying the image") |
| `docker compose run --rm client restore <buddy node id> [dir]` | One-shot restore of every file in your latest snapshot on that buddy, decrypted, then exits. `<buddy node id>` is required (Buddies card). `[dir]` is optional and is a path *inside the container*; the default is `/restored/<node id>`, which is `RESTORE_DIR_HOST/<node id>` on the host. Needs the same `BACKUP_PASSPHRASE` and a device token from the same account |
| `cargo build --release` | Build from source (Rust 1.85+, edition 2024) |
| `docker build -t backup-buddies-client .` | Build the image yourself |

The client binary itself takes no flags. Its only subcommand is
`restore`; with no arguments it runs as the normal background service.
Everything else is set in `.env`.

### Settings (`.env`)

The client reads these once at startup, so restart after a change
(`docker compose up -d`). `.env.example` has the same list with longer
explanations.

**Required**

| Variable | What it is |
|---|---|
| `DEVICE_TOKEN` | From your account dashboard's Devices card ("Add device"). Shown once; if lost, remove the device there and add a new one |
| `BACKUP_PASSPHRASE` | Encrypts everything before it leaves this machine. It never leaves this machine and **can't be recovered**. Under 12 characters logs a warning. To restore a backup on another device, that device needs the same passphrase |
| `API_URL` | The service's API, `https://api.filegarden.net`. Leave as-is |

**Folders** (on the host; mounted into the container at fixed paths)

| Variable | Default | Container path | What it is |
|---|---|---|---|
| `BACKUP_DIR_HOST` | unset (receive-only device) | `/backup` (read-only) | Your files, which get backed up |
| `BUDDY_FILES_DIR_HOST` | `./buddy-files` | `/buddy-files` | What buddies store with you (encrypted). Needs the space you pledged |
| `RESTORE_DIR_HOST` | `./restored` | `/restored` | Where restores are written |
| `DATA_DIR_HOST` | `./config` | `/data` | This device's identity key and bookkeeping, and `excludes.txt` (see "Excluding files"). **Keep it**: losing it means a new identity |

**Optional**

| Variable | Default | What it does |
|---|---|---|
| `RELAY_URL` | `https://relay.filegarden.net` | Relay used when a direct connection isn't possible |
| `PUID`, `PGID` | unset (runs as root) | Run as this user and group id (`id -u`, `id -g`), so files it creates are yours. `PGID` defaults to `PUID`. Needed for most NFS shares |
| `DASHBOARD_PORT` | `8080` | Port for this device's status page |
| `DASHBOARD_BIND` | `0.0.0.0:<DASHBOARD_PORT>` | Full address to listen on. `127.0.0.1:8080` doesn't listen on the network at all |
| `DASHBOARD_PASSWORD` | unset (dashboard locked) | Password for the first dashboard login. Once you change it on the dashboard, the stored one is used instead. See "Logging in" |
| `DASHBOARD_USER` | `admin` | User name for the dashboard login |
| `SYNC_PORT` | `11235` | UDP port for buddy connections. Forward it on your router for direct (non-relayed) connections |
| `SCAN_INTERVAL_SECS` | `30` | How often to look for changes and sync, in seconds. At least 5 |
| `STALE_AFTER_SECS` | `600`, or 3× the scan interval if longer | How long without a successful cycle before the dashboard calls a buddy stale |
| `DEFAULT_EXCLUDES` | on | `off` (or `false`, `0`, `no`) stops skipping the built-in list of poor fits (PST, live databases, VM disks, temp files). See "Excluding files" |
| `ALLOW_EMPTY_BACKUP_DIR` | off | `true` (or `1`, `yes`) lets an empty backup folder be backed up as an empty snapshot. Set it for one restart after a deliberate cleanup, then remove it: while on, it disables the missing-drive guard |
| `UPDATE_CHECK_URL` | derived from `API_URL` (`https://app.filegarden.net/client/Cargo.toml`) | Where to check for a newer version (every hour). `off` disables the check |

**Set by the image or compose file; don't set these yourself**

| Variable | What it is |
|---|---|
| `BACKUP_DIR`, `BUDDY_FILES_DIR`, `RESTORE_DIR`, `DATA_DIR` | Container-side folder paths (`/backup`, `/buddy-files`, `/restored`, `/data`) |
| `BB_INSTALL_KIND` | `image` for the published image, `source` for an `install.sh` build. Decides which update command the dashboard shows |

### Status dashboard endpoints

The page at `http://<machine>:8080` is backed by a small JSON API on the
same port. Every route except the login page needs a login session; see
"Logging in" above. API calls without one get `401`, pages redirect to `/login`.
`<node_id>` is a buddy's Iroh node id. Every `/api/buddies/...` call
connects to that buddy live, and answers `502` if the buddy can't be
reached.

| Route | What it does |
|---|---|
| `GET /` | The dashboard page |
| `GET /login`, `POST /login` | Login page, and the form it posts (`username`, `password`). Sets the session cookie |
| `POST /logout` | Ends the session |
| `POST /api/password` | Change the dashboard password: body `{"current", "new"}` (8+ characters). Logs out other sessions |
| `GET /api/excludes` | Your exclude lines (`own`), the built-in list, whether it's on, and where the file is |
| `POST /api/excludes` | Save your exclude lines: body `{"own": "..."}`. `400` with the reason if a line is invalid (nothing is saved) |
| `GET /api/activity?filter=&limit=` | Activity events, newest first. `filter`: `all` (default), `backups`, `problems` or `security`; `limit` default 50, at most 200 |
| `GET /api/logs` | The last 300 log lines (memory only) |
| `GET /api/status` | Everything the page shows: this device, version and update status, disk, the last backup cycle, and per-buddy pledges, usage, health and bandwidth |
| `GET /api/buddies/<node_id>/files` | Your backup on that buddy: `files` (each file's `path`, `size` and whether it's `deleted`, i.e. only in older snapshots) and `stored` (the pack files as the buddy holds them: `remote`, `size`) |
| `GET /api/buddies/<node_id>/disk` | That buddy's real disk space and total commitments |
| `GET /api/buddies/<node_id>/versions?path=<path>` | Earlier versions of one file across the snapshots still kept |
| `GET /api/buddies/<node_id>/peek?path=<remote>` | The first 256 bytes of one pack (a `remote` from `stored`) exactly as that buddy holds it (still encrypted), as `{"path", "hex"}`. For "What your buddy sees" |
| `POST /api/restore/<node_id>` | Restore to `RESTORE_DIR_HOST/<node_id>/`. Body `{"paths": [...]}`; empty or missing means everything |
| `GET /api/buddies/<node_id>/restore-progress` | Progress of the latest restore from that buddy (`{"active": false}` if none) |
| `POST /api/restore-version/<node_id>` | Restore one earlier version. Body `{"path", "version"}`. It's written next to the normal restore with a suffix and never overwrites it |

### What it sends to the service

With `DEVICE_TOKEN` as a bearer token, and
`User-Agent: backup-buddies-client/<version>`:

| Call | When | Purpose |
|---|---|---|
| `GET /devices/me` | Startup, until it has succeeded once | Learns its account id, which is part of the encryption key. Saved in `DATA_DIR`, so later starts work even if the service is unreachable |
| `PUT /devices/me/node-id` | Startup | Registers this device's Iroh node id so buddies can find it |
| `GET /devices/me/buddies?relay_mb=<n>` | About every 30 s | Gets the buddies' node ids and pledges and whether the account is `paused`, and reports relay megabytes used since the last report |

Plus the update check (above). File contents, names and the passphrase
are never sent to the service.

### Buddy-to-buddy protocol

Clients talk to each other directly over Iroh (QUIC), ALPN
`backup-buddies/sync/1`, falling back to the relay when needed. Each
request is a framed message (`src/protocol.rs`): `Hello` (protocol
version, currently 5), `Ping`, `DiskStats`, and the repository calls
`RepoList`, `RepoRead`, `RepoWrite` and `RepoRemove`, which store, list,
read and remove opaque repository files by kind and id. A buddy only ever
lists, returns or removes what the connecting device itself stored there,
identified by its node id. The whole-file requests of protocol versions
1–4 were dropped in client 0.21.0.

## License

Copyright (C) 2026 Spencer LeBlanc.

The Backup Buddies client is free software, licensed under the
[GNU General Public License v3.0](LICENSE) (GPL-3.0-only). You can read,
build, change and share it; if you distribute a modified version, it must
stay under the same license with its source available.

This covers the client only — the program that runs on your machine, reads
your files and encrypts them. The hosted service it talks to (accounts,
pairing, the relay at relay.filegarden.net) is run separately at
filegarden.net.

**Building from source:** `cargo build --release` (Rust 1.85+, edition
2024), or `docker build .` in this folder. `install.sh` builds this same
code from source; the published image is built from it too.

**Security issues:** please report privately to support@filegarden.net.

**Bugs and ideas:** please use
[backup-buddies-feedback](https://github.com/mspencerl87/backup-buddies-feedback/issues).
For problems with your account, login or billing, use Contact support on
your dashboard instead, so your details stay private.

**Contributions:** pull requests aren't accepted yet. This repository is
published from the maintainer's own, so changes merged here would be
overwritten. You're welcome to fork it under the GPL.
