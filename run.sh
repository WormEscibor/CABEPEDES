#!/bin/sh
set -eu
BASE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

# Normal use installs/starts CABEPEDES under LaunchAgent so the server is
# independent of the terminal process. FOREGROUND mode is only for QA/debug.
if [ "${CABEPEDES_FOREGROUND:-0}" = "1" ]; then
  PYTHON=""
  for CANDIDATE in "${CABEPEDES_PYTHON:-}" /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3 python3; do
    if [ -n "$CANDIDATE" ] && command -v "$CANDIDATE" >/dev/null 2>&1; then PYTHON="$CANDIDATE"; break; fi
  done
  if [ -z "$PYTHON" ]; then
    echo "Python 3 tidak ditemukan." >&2
    exit 1
  fi
  exec "$PYTHON" "$BASE_DIR/server.py"
fi

exec "$BASE_DIR/bootstrap.sh"
