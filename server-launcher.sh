#!/bin/sh
set -eu
BASE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
PYTHON=""
for CANDIDATE in "${CABEPEDES_PYTHON:-}" /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
  if [ -n "$CANDIDATE" ] && [ -x "$CANDIDATE" ]; then PYTHON="$CANDIDATE"; break; fi
done
if [ -z "$PYTHON" ]; then
  PYTHON="$(command -v python3 2>/dev/null || true)"
fi
if [ -z "$PYTHON" ]; then
  exit 78
fi
exec "$PYTHON" "$BASE_DIR/server.py"
