#!/bin/sh
# Container entrypoint. With PUID/PGID unset, runs the client as root,
# exactly as before. With them set (see .env.example), it:
#   1. makes sure the client's own folders (config, buddy files, restores)
#      belong to that user and group, and
#   2. runs the client as that user, so everything it creates on the host
#      (restored files especially) belongs to you rather than root.
# BACKUP_DIR (your files) is mounted read-only and never touched.
set -eu

CLIENT_BIN="${CLIENT_BIN:-/usr/local/bin/backup-buddies-client}"

if [ "$(id -u)" != "0" ] || [ -z "${PUID:-}" ]; then
  exec "$CLIENT_BIN" "$@"
fi

PGID="${PGID:-$PUID}"
case "$PUID$PGID" in
  *[!0-9]*) echo "PUID and PGID must be numbers (got PUID=$PUID PGID=$PGID). Run 'id -u' and 'id -g' on the host." >&2; exit 1 ;;
esac

# Only walk a folder when something near the top isn't owned yet: the
# folder itself, a buddy's folder inside it, or a file directly in one of
# those. A full recursive check on every start would mean statting every
# file a buddy has stored — potentially millions.
needs_chown() {
  [ -n "$(find "$1" -maxdepth 2 \( ! -user "$PUID" -o ! -group "$PGID" \) -print -quit 2>/dev/null)" ]
}

DATA_DIR="${DATA_DIR:-/data}"
for dir in "$DATA_DIR" "${BUDDY_FILES_DIR:-}" "${RESTORE_DIR:-}"; do
  [ -n "$dir" ] || continue
  mkdir -p "$dir"
  if needs_chown "$dir"; then
    echo "Setting ownership of $dir to $PUID:$PGID (one-time, may take a moment for a large folder)..."
    # Can fail on a network share that maps root to nobody (NFS
    # root_squash). That's fine as long as the share already lets
    # PUID:PGID write there — the client's own startup check will say
    # clearly if it can't.
    chown -R "$PUID:$PGID" "$dir" 2>/dev/null \
      || echo "Note: couldn't change ownership of $dir (a network share?). Continuing as $PUID:$PGID." >&2
  fi
done

exec setpriv --reuid="$PUID" --regid="$PGID" --clear-groups -- "$CLIENT_BIN" "$@"
