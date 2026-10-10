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
scans that folder, encrypts anything new or changed with
`BACKUP_PASSPHRASE`, and sends just the diff to each buddy's device.
Deleted files are told apart too, so your buddy's copy mirrors yours
rather than only ever growing. A receive-only device (no `BACKUP_DIR_HOST`
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
- **Does:** keep sending only the delta each cycle. A cycle lists the
  folder (metadata only) and only re-reads a file whose size or modified
  time changed since last time; unchanged files are never read, so an
  unchanged folder costs a listing, not a re-read. Files whose content
  changed are re-sent whole (see "Large folders and large files" below).
- **Does:** keep a short backstop when a file is overwritten or deleted —
  the live copy plus its last 2 replaced versions are kept on your
  buddy's disk, browsable and individually restorable from the local
  dashboard (see "File versions" below). Not full version history, just
  protection against a bad overwrite or an accidental delete.
- **Does not:** send your passphrase anywhere. It's used locally to
  derive an encryption key and never appears in any API call, log line,
  or network request. If you lose it, data stored with your buddy cannot
  be recovered — there's no "forgot passphrase" flow, by design.
- **Does not:** let your buddy read your data. Their client stores
  whatever bytes you send it verbatim, without trying to decrypt them —
  and only ever lets *you* list or fetch back what *you* stored with
  them, never another buddy's data.

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
  catalogs, encrypted containers). They work, but any change re-sends the
  whole file: a 20 GB file changing daily is around 600 GB a month over
  both your connections. If it goes through the relay, that counts toward
  the free monthly relay allowance (syncing pauses past it until the 1st)
  or is billed per GB on a paid plan. Fine if they rarely change.
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
anything else (see "Excluding files" below). Your buddy can see file
names, paths and sizes (never contents), so don't put anything private in
a file or folder name.

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
`.env` turns the built-in list off.

**Your own list** is `excludes.txt` in the config folder
(`DATA_DIR_HOST`, `./config` by default). The client creates it, with
examples, the first time it starts. One pattern per line:

| Pattern | Excludes |
|---|---|
| `*.iso` | any `.iso` file, in any folder |
| `/Downloads` | the `Downloads` folder at the top of your backup folder only (and everything in it) |
| `node_modules` | every folder named `node_modules`, at any depth |
| `Photos/**/*.tmp` | `.tmp` files anywhere under `Photos` |
| `(?i)*.mkv` | `.mkv` in any case (patterns are case-sensitive otherwise) |
| `!*.pst` | nothing: it **brings back** `.pst` files the built-in list would skip |

`*` matches within one folder, `**` across folders; `?`, `[a-z]` and
`{jpg,png}` work too. Lines starting with `//` (or `# `) are comments. The
**first** line that matches a file decides, and your list is checked
before the built-in one, so a `!` line goes above whatever it makes an
exception to. Edits apply on the next check; no restart needed. A line the
client can't understand stops backups with an error naming the line,
rather than being skipped. The dashboard shows how many files (and
skipped folders) were excluded under **Local files**.

**Excluding something that's already backed up removes it from your
buddy**, the same way deleting it would: they keep the last copy for 30
days (see "File versions"), then it's gone. The log says how many files
that applies to. If your list would exclude everything while your buddy
still holds files, the client stops and says so instead of removing them
all.

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
their pledge to you and how much of it is used, how many files you've
sent each other and how much that totals to, and the result of the last
backup cycle (or ping, for a buddy you're not backing anything up to).
There's also a "Restore from this buddy" button, which does the same
thing as the `restore` command below and writes to the same place
(`RESTORE_DIR_HOST/<their node id>/`), showing you the result right there
instead of needing a terminal.

**It has no login of its own**, and that restore button is a real action
— not just a read-only view. By default it's open on every interface
(most people run this headless and manage it from elsewhere on their
network), so anyone who can reach this machine on that port can see your
buddy/pledge info and trigger a restore. If this machine is reachable
from somewhere you don't trust — the open internet, a shared or guest
network — either restrict it to loopback (`DASHBOARD_BIND=127.0.0.1:8080`
in `.env`; the compose file uses host networking, so there's no port
mapping to edit) and reach it over SSH tunnel or VPN instead, or put a
reverse proxy with auth in front of it.

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
restores everything it's offered and exits, rather than running as part
of the normal daemon loop.

## Building locally

```bash
cargo build --release
# or, to build the Docker image yourself instead of pulling it:
docker build -t backup-buddies-client .
```

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

Since 0.6.0 the client's own local dashboard does the same check: every 6
hours it reads that same `/client/Cargo.toml` (the `app.` sibling of
`API_URL`'s `api.` host, or `UPDATE_CHECK_URL`; `off` disables it) and the
"This Device" card shows "Up to date" or "Update available: x.y.z" with the
update command for that install kind (the CI-built image sets
`BB_INSTALL_KIND=image` and shows `docker compose pull && docker compose up -d`;
a local build shows the `install.sh --update` command). If the check can't complete (offline), nothing is shown
rather than a false "up to date". It deliberately doesn't use GitHub
releases: the source repo is private, and an `install.sh` build has no
`.git` to read a commit from, whereas every install knows its own version.

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
`DATA_DIR/restored` when unset — the layout before they were split out — so
an older install that hasn't added them keeps working. If `BUDDY_FILES_DIR`
points at an empty folder while buddy files are still in `DATA_DIR/received`
(what an existing install gets after `install.sh --update` brings in the new
`docker-compose.yml` but keeps its `.env`), the client keeps using the old
location and logs a warning with how to move them — starting on the empty
folder would make its buddies' backups look missing while `usage.json` still
counted them. If *both* folders hold buddy files, it refuses to start until
they're merged. Pointing `BUDDY_FILES_DIR_HOST` at the old
`DATA_DIR_HOST/received` folder is fine — it's detected as the same folder.

Config (`DATA_DIR`):

- `iroh_secret_key` — this device's identity. Deleting it means the
  device re-registers under a new identity next startup (update it on
  your dashboard, or just remove and re-add the device there).
- `index.sqlite` (+ `-wal`/`-shm`) — this device's index (SQLite): the
  size, modified time and hash of each file in `BACKUP_DIR`, and per
  buddy, what was last sent them (path, size, hash, encrypted size).
  Updated one row at a time as files land. Deleting it means the next
  cycle re-reads every file and re-sends everything — wasteful, but
  harmless; it doesn't affect what's actually stored on either side.
  Replaces the old `manifest-<buddy>.json` files, which are imported on
  first start of 0.5.0 and renamed `*.json.migrated` (safe to delete).
- `usage.json` — `{ "<buddy node id>": <bytes received from them> }`,
  tracked per buddy and checked against their pledge
  (`buddy_pairings.pledged_bytes`, fetched from the API every 30s) before
  accepting any incoming file. Deleting it resets what's counted toward
  each buddy's pledge back to zero — the underlying buddy files are
  untouched, so this can desync the two if used carelessly.
- `bandwidth.json` — lifetime bytes moved via relay vs. direct (see
  "Relay bandwidth" below). Deleting it just resets the dashboard's
  counter back to zero.

Buddy files (`BUDDY_FILES_DIR`):

- `<buddy node id>/` — the actual files a buddy has backed up with you,
  stored encrypted and under the same relative paths they back them up
  with on their end. This device never attempts to decrypt them — it has
  no reason to ever hold the sender's passphrase.
- `<buddy node id>/.versions/` — backup slots for that buddy's files,
  kept when a file is overwritten or deleted (see "File versions" below).
  Deleting this folder just gives up that recovery history; it doesn't
  touch the live files.

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
  the wrong disk. Deleting `buddy-files-id` deliberately starts over. A
  marker left behind by `mv received/* new/` (globs skip dotfiles) is
  carried over automatically, but only once the new folder has files in it.
- **Your files:** if `BACKUP_DIR` scans completely but comes back empty
  while the buddy holds files from it, the cycle fails with an explanation
  instead of sending a delete for every file. `ALLOW_EMPTY_BACKUP_DIR=true`
  overrides it; remove it again afterwards (the client warns at startup
  while it's set).
- **Unreadable files or folders:** an unreadable file is reported as a
  failed file and the rest of the cycle carries on (it used to abort the
  whole cycle). An unreadable folder is reported and pauses *all*
  deletions that cycle — its contents would otherwise look deleted.

## Backup progress on the dashboard (0.5.1)

While a backup cycle runs, each buddy card on the local dashboard shows a
progress bar: "checking files" (how many checked, and how far through a
changed file it's reading), then "backing up" (files and bytes done, speed,
time left, current file). It disappears when the cycle ends and the normal
last-cycle line takes over. Served as `in_progress` on each buddy in
`/api/status`.

## Interrupted uploads resume (0.8.0)

A big file (256 MB or more) whose upload is cut off partway — a dropped
connection, a restart on either side — carries on from where it stopped on
a later cycle instead of starting again from zero.

Because every encryption uses a fresh random key, re-encrypting the file
would give different bytes, so the sender keeps the exact encrypted copy
it's sending in `DATA_DIR/outgoing/` and resumes from that. The copy is
encrypted like everything that leaves this machine, and is deleted as
soon as the buddy confirms the file. The buddy keeps the partial upload
under `<sender>/.incoming/resume/`, and only stores the file once the
hash of the whole thing checks out.

- Needs both buddies on 0.8.0. With an older buddy, uploads work as before.
- The copy needs free space on DATA_DIR's disk about the size of the file
  (plus 1 GB to spare). Without it, the file is sent the old way, with no
  resume.
- If the file changes before the upload finishes, both copies are
  discarded and the new version is sent whole.
- If the sender's client is stopped while it's still encrypting, that copy
  can't be resumed from and the file starts over (once). Copies and
  partials nobody comes back for are deleted after 7 days.

## Known issue: dropped connections on a local network

Occasionally a long transfer between buddies on the same local network
loses its connection partway through, usually minutes in, logged as
`failed closing path err=LastOpenPath` and then `connection lost` /
`timed out`. The next cycle carries on: big files resume (above), smaller
ones are re-sent. Seen so far only with two test clients on the same
machine, where every interface address, including the Docker bridge
(`docker0`, 172.17.0.1), is offered as a route; the cause isn't confirmed.
If you run two clients on one host and see it often, that's the likely
reason.

## Large folders and large files (0.5.0)

- **Change detection:** see `index.sqlite` above — an unchanged file is
  never read again. `SCAN_INTERVAL_SECS` (default 30, minimum 5) sets how
  often a cycle runs; staleness on the dashboard scales with it.
- **Streaming:** hashing, encryption, upload, storage on the buddy's side,
  download and decryption all stream in ~256 KiB pieces, so memory doesn't
  depend on file size (tested: a 6 GB file on a 7 GB-RAM machine, peak
  ~263 MB, almost all of it the one-time key derivation below). The
  per-file limit is 1 TB (was 5 GB). Uploads land in a hidden `.incoming/`
  folder on the buddy's side and are moved into place only once complete
  and verified; leftovers from an interrupted upload are cleared on start.
  Restores are written to a temporary file and moved into place only once
  the whole file decrypted and authenticated.
- **Encryption key:** files used to be encrypted straight to the
  passphrase, which runs scrypt (~1.5 s of CPU) for *every* file — 20,000
  photos took ~8 hours. Now the passphrase goes through scrypt once at
  startup (`log_n=18, r=8`, ~1 s and 256 MB, fixed salt) to derive an
  X25519 key, and files are encrypted to that key. The passphrase alone
  still recovers everything; files encrypted the old way still restore
  (decryption tries both). Trade-off of the fixed salt: weak passphrases
  are easier to attack in bulk, so passphrase length matters (the client
  warns under 12 characters); a per-account salt is on the launch
  checklist as later hardening.
- **Large file lists:** a buddy's file list is sent in chunks of 5,000
  (`ListStream`) — the old single-message list broke above ~10,000 files,
  which broke reconciliation, restore and the file browser.
- **Mixed versions:** an updated client asks a buddy its protocol version
  (`Hello`) before uploading. A buddy still on ≤0.4 gets the old upload
  format, limited to files up to 512 MB (the old format needs the whole
  encrypted file in memory to hash it first); bigger files wait, reported
  as "your buddy's client is out of date". Updated clients still accept
  every old request, so an old client keeps working against a new one.
- Tested end to end (`src/e2e_tests.rs`): two real endpoints over
  localhost, real send/receive/reconcile/restore code. 20,000 small files:
  first backup 41 s (was ~8 h), unchanged cycle 0.14 s, restore 23 s.

## Disk safety: pledges vs. the real disk

A pledge is just a number two accounts agreed on over the API — it's not a
reservation the filesystem enforces. On top of the per-buddy pledge check
above, every incoming file is also checked against the *real* free space on
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

A buddy's copy used to just mirror yours exactly: whatever you last sent
them is all they have. Now, whenever a file you'd already backed up gets
overwritten or deleted, the previous content isn't discarded — it's kept
as a numbered backup slot (`.versions/` inside that buddy's folder in `BUDDY_FILES_DIR`
on the receiving end), up to the 2 most recent replacements. So at
any time, up to 3 copies of a file exist on your buddy's disk: the current
one (if it still exists) plus its last 2 predecessors. A delete isn't
destructive either — the deleted content becomes the newest backup slot
rather than vanishing, so a fat-fingered local delete is recoverable the
same way a bad overwrite is.

To get one back: open **Browse files** on a buddy's card, click
**History** next to a file, and pick a version to restore. It's written
to `RESTORE_DIR/<buddy>/<path>.v<N>.bak` — alongside, never over, a
normal restore of that file — so you can compare before deciding what to
keep.

This is a backstop against corruption, a bad sync, or an accidental local
delete, not full version history — only the live copy and its last 2
predecessors are kept.

**Backup copies are kept for 30 days (0.8.2).** A copy is removed for good
30 days after it was replaced or deleted (History shows "kept … ago,
removed in N days"). The buddy storing it does this, at startup and once a
day. Pledges only count live files, so without a limit, someone who backs
up 100 GB, deletes it and backs up another 100 GB would leave 200 GB on
their buddy's disk against a 100 GB pledge. Copies made before 0.8.2 are
dated by when they were uploaded, so the first run after updating re-dates
them to that day instead of removing them. Buddies on older clients keep
copies indefinitely.

**Delete permanently (0.9.0).** To free the space sooner, a deleted file
in **Browse files** has a **Delete permanently** button. After a
confirmation, the buddy removes the copies it's keeping of that file, so it
can no longer be restored. Only files you've already deleted have the
button, and the buddy refuses if the file still exists there, so it can't
remove a current file. Both buddies need 0.9.0.

## Buddy health — staleness and per-file failures

The pill next to each buddy's name shows the *last* cycle's result, but a
buddy could look fine on that alone while quietly failing for a while
(say, a one-off error that happens to land on the very last cycle you
happened to check). The dashboard tracks this separately: if a buddy
hasn't had a *successful* cycle in over `STALE_AFTER_SECS` (10 minutes by
default — see `.env.example`), a red **stale** badge shows up next to
their status, saying how long it's actually been since something last
went through.

Separately, if specific files keep failing to send or delete while the
cycle otherwise runs fine, they're called out by name under that buddy's
card (capped at the first 10, if there are more) rather than just logged
and silently retried forever in the background. A cycle with any failing
files is no longer reported as fully "ok" either, for the same reason.

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
| `docker compose run --rm client restore <buddy node id> [dir]` | One-shot restore of everything that buddy holds for you, decrypted, then exits. `<buddy node id>` is required (Buddies card). `[dir]` is optional and is a path *inside the container*; the default is `/restored/<node id>`, which is `RESTORE_DIR_HOST/<node id>` on the host. Needs the same `BACKUP_PASSPHRASE` and a device token from the same account |
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
| `DASHBOARD_BIND` | `0.0.0.0:<DASHBOARD_PORT>` | Full address to listen on. `127.0.0.1:8080` keeps the page local to this machine |
| `SYNC_PORT` | `11235` | UDP port for buddy connections. Forward it on your router for direct (non-relayed) connections |
| `SCAN_INTERVAL_SECS` | `30` | How often to look for changes and sync, in seconds. At least 5 |
| `STALE_AFTER_SECS` | `600`, or 3× the scan interval if longer | How long without a successful cycle before the dashboard calls a buddy stale |
| `DEFAULT_EXCLUDES` | on | `off` (or `false`, `0`, `no`) stops skipping the built-in list of poor fits (PST, live databases, VM disks, temp files). See "Excluding files" |
| `ALLOW_EMPTY_BACKUP_DIR` | off | `true` (or `1`, `yes`) lets an empty backup folder sync as "everything deleted". Set it for one restart after a deliberate cleanup, then remove it: while on, it disables the missing-drive guard |
| `UPDATE_CHECK_URL` | derived from `API_URL` (`https://app.filegarden.net/client/Cargo.toml`) | Where to check for a newer version (every 6 hours). `off` disables the check |

**Set by the image or compose file; don't set these yourself**

| Variable | What it is |
|---|---|
| `BACKUP_DIR`, `BUDDY_FILES_DIR`, `RESTORE_DIR`, `DATA_DIR` | Container-side folder paths (`/backup`, `/buddy-files`, `/restored`, `/data`) |
| `BB_INSTALL_KIND` | `image` for the published image, `source` for an `install.sh` build. Decides which update command the dashboard shows |

### Status dashboard endpoints

The page at `http://<machine>:8080` is backed by a small JSON API on the
same port. It has **no authentication** (see "Status dashboard" above).
`<node_id>` is a buddy's Iroh node id. Every `/api/buddies/...` call
connects to that buddy live, and answers `502` if the buddy can't be
reached.

| Route | What it does |
|---|---|
| `GET /` | The dashboard page |
| `GET /api/status` | Everything the page shows: this device, version and update status, disk, the last backup cycle, and per-buddy pledges, usage, health and bandwidth |
| `GET /api/buddies/<node_id>/files` | What that buddy holds for you right now |
| `GET /api/buddies/<node_id>/disk` | That buddy's real disk space and total commitments |
| `GET /api/buddies/<node_id>/versions?path=<path>` | Older saved copies of one file |
| `POST /api/restore/<node_id>` | Restore to `RESTORE_DIR_HOST/<node_id>/`. Body `{"paths": [...]}`; empty or missing means everything |
| `GET /api/buddies/<node_id>/restore-progress` | Progress of the latest restore from that buddy (`{"active": false}` if none) |
| `POST /api/restore-version/<node_id>` | Restore one older copy. Body `{"path", "version"}`. It's written next to the normal restore with a suffix and never overwrites it |
| `POST /api/buddies/<node_id>/purge` | "Delete permanently": body `{"path"}`. Asks the buddy to drop the saved copies of a file you've deleted. Refused while the file still exists |

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
version, currently 4), `Ping`, `Put` / `PutStream` / `PutResumable`
(upload, the last one resumable for large files), `Delete`, `List` /
`ListStream`, `Get`, `DiskStats`, `ListVersions`, `GetVersion` and
`PurgeDeleted`. A buddy only ever lists, returns or deletes what the
connecting device itself stored there, identified by its node id.

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
