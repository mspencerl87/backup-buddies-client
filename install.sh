#!/usr/bin/env bash
# One-liner installer for the Backup Buddies client:
#
#   curl -fsSL https://app.filegarden.net/client/install.sh | bash
#
# Downloads everything needed to build and run the client (it's served
# directly from the app, not from the project's private GitHub repo, so
# this works without any GitHub access). Creates ./backup-buddies-client/
# in the current directory and leaves you with instructions, never starts
# anything on its own.
#
# Updating an existing install (run from inside backup-buddies-client/, or
# from the folder that contains it):
#
#   curl -fsSL https://app.filegarden.net/client/install.sh | bash -s -- --update
#
# Works for both kinds of install:
#   - built from source by this script: replaces only the code (source,
#     Dockerfile, compose file) and rebuilds;
#   - the setup page's two-file setup (docker-compose.yml running the
#     published client image + .env): pulls the latest image and restarts.
#     Its docker-compose.yml is the user's own and is left as-is.
# Never touches .env (device token, backup passphrase) or the data folders
# (./config or ./data: this device's identity; ./buddy-files: the backups it
# holds for its buddies, unless .env points them elsewhere) — deleting
# the folder and reinstalling would lose both, so never update that way.

set -euo pipefail

MODE="install"
if [ "${1:-}" = "--update" ]; then
  MODE="update"
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: docker is not installed. Install Docker first: https://docs.docker.com/get-docker/" >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "Error: 'docker compose' isn't available (you may only have the older standalone docker-compose)." >&2
  echo "Install the Compose plugin: https://docs.docker.com/compose/install/" >&2
  exit 1
fi

BASE_URL="${BB_CLIENT_BASE_URL:-https://app.filegarden.net/client}"
DEST="backup-buddies-client"

TOP_FILES="docker-compose.yml .env.example Dockerfile docker-entrypoint.sh Cargo.toml Cargo.lock"
# Every module main.rs pulls in via `mod ...;` — Caddy serves the whole
# apps/client/ tree statically but doesn't offer directory listing, so this
# has to be an explicit list rather than something discovered at runtime.
# Keep this in sync with apps/client/src/*.rs — a new module there needs
# adding here too, or customers' builds will fail on a missing `mod`.
SRC_FILES="main.rs backup.rs bandwidth.rs crypto.rs dashboard.rs index.rs manifest.rs netinfo.rs protocol.rs receive.rs restore.rs update_check.rs"
# dashboard.rs embeds these via include_str! at compile time — same
# keep-in-sync caveat as SRC_FILES above, against apps/client/assets/*.
ASSET_FILES="favicon.svg mark.svg"

# Downloads the full set of client files into directory $1.
download_into() {
  local dir="$1"
  mkdir -p "$dir/src" "$dir/assets"
  for f in $TOP_FILES; do curl -fsSL -o "$dir/$f" "$BASE_URL/$f"; done
  for f in $SRC_FILES; do curl -fsSL -o "$dir/src/$f" "$BASE_URL/src/$f"; done
  for f in $ASSET_FILES; do curl -fsSL -o "$dir/assets/$f" "$BASE_URL/assets/$f"; done
}

client_version() {
  sed -n 's/^version = "\(.*\)"/\1/p' "$1" 2>/dev/null | head -n 1
}

# Installed by this script: builds the client from source.
is_source_install() {
  [ -f "$1/.env" ] && [ -f "$1/docker-compose.yml" ] && grep -q '^name = "backup-buddies-client"' "$1/Cargo.toml" 2>/dev/null
}

# Set up from the setup page (apps/web/setup.html): just a compose file that
# runs the published client image, plus .env — no source code.
is_image_install() {
  [ -f "$1/.env" ] && [ -f "$1/docker-compose.yml" ] && [ ! -f "$1/Cargo.toml" ] \
    && grep -qE '^[[:space:]]*image:[[:space:]]*[^[:space:]#]*backup-buddies/client' "$1/docker-compose.yml"
}

if [ "$MODE" = "update" ]; then
  TARGET=""
  KIND=""
  for dir in "." "$DEST"; do
    if is_source_install "$dir"; then TARGET="$dir"; KIND="source"; break; fi
    if is_image_install "$dir"; then TARGET="$dir"; KIND="image"; break; fi
  done
  if [ -z "$TARGET" ]; then
    echo "Error: no existing install found here. Run this from inside your client folder" >&2
    echo "(the one with .env and docker-compose.yml in it), or from the folder that contains" >&2
    echo "backup-buddies-client/." >&2
    exit 1
  fi
  cd "$TARGET"

  if [ "$KIND" = "image" ]; then
    echo "Found an install that runs the published client image. Pulling the latest and restarting..."
    docker compose pull
    docker compose up -d
    echo
    echo "Done. Your .env, docker-compose.yml and data folders were not touched."
    echo "Check it with: docker compose logs -f"
    exit 0
  fi

  OLD_VERSION="$(client_version Cargo.toml)"
  # Download everything to a staging folder first, so a failed or partial
  # download never leaves a half-updated client behind.
  STAGING="$(mktemp -d)"
  trap 'rm -rf "$STAGING"' EXIT
  echo "Downloading the latest client from $BASE_URL ..."
  download_into "$STAGING"
  NEW_VERSION="$(client_version "$STAGING/Cargo.toml")"

  # Keep a copy if someone hand-edited their compose file.
  if [ -f docker-compose.yml ] && ! cmp -s docker-compose.yml "$STAGING/docker-compose.yml"; then
    cp docker-compose.yml docker-compose.yml.bak
    echo "Note: your docker-compose.yml differed from the new one — saved a copy as docker-compose.yml.bak"
  fi

  mkdir -p src assets
  for f in $TOP_FILES; do cp "$STAGING/$f" "$f"; done
  for f in $SRC_FILES; do cp "$STAGING/src/$f" "src/$f"; done
  for f in $ASSET_FILES; do cp "$STAGING/assets/$f" "assets/$f"; done

  echo "Updated client code: ${OLD_VERSION:-unknown} -> ${NEW_VERSION:-unknown}. Your .env and data folders were not touched."
  echo "Rebuilding and restarting (a few minutes)..."
  docker compose up -d --build
  echo
  echo "Done. Check it with: docker compose logs -f"
  exit 0
fi

if [ -d "$DEST" ]; then
  echo "Error: ./$DEST already exists. To update it, run:" >&2
  echo "  curl -fsSL $BASE_URL/install.sh | bash -s -- --update" >&2
  echo "(Don't delete it to reinstall — its .env and data folders hold your device token, passphrase, and backups.)" >&2
  exit 1
fi

echo "Downloading client files from $BASE_URL ..."
download_into "$DEST"
cd "$DEST"

cp .env.example .env

cat <<'EOF'

Downloaded to ./backup-buddies-client/

Next steps:
  1. Edit backup-buddies-client/.env — set DEVICE_TOKEN (from your
     dashboard's Devices card) and BACKUP_PASSPHRASE (something only you
     know; it never leaves this machine and can't be recovered if lost).
     Then set the folders: BACKUP_DIR_HOST (your files) and
     BUDDY_FILES_DIR_HOST (a folder with room for what your buddy stores
     with you). See the FOLDERS section in .env for examples.
  2. cd backup-buddies-client && docker compose up -d
     (builds the image locally the first time — a few minutes)
  3. docker compose logs -f

EOF
