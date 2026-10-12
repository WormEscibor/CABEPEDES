#!/bin/sh
set -eu

SOURCE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
INSTALL_PARENT="$HOME/Applications"
INSTALL_DIR="$INSTALL_PARENT/CABEPEDES"
PLIST_DIR="$HOME/Library/LaunchAgents"
PLIST="$PLIST_DIR/id.kemkes.csirt.cabepedes.plist"
LABEL="id.kemkes.csirt.cabepedes"

find_python() {
  PYTHON=""
  for CANDIDATE in "${CABEPEDES_PYTHON:-}" /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
    if [ -n "$CANDIDATE" ] && [ -x "$CANDIDATE" ]; then PYTHON="$CANDIDATE"; break; fi
  done
  if [ -z "$PYTHON" ]; then PYTHON="$(command -v python3 2>/dev/null || true)"; fi
}

xml_escape() {
  printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
}

if [ "$(uname -s)" != "Darwin" ]; then
  /usr/bin/osascript -e 'display dialog "CABEPEDES release ini ditujukan untuk macOS." buttons {"OK"} default button "OK" with title "CABEPEDES"' >/dev/null 2>&1 || true
  echo "CABEPEDES membutuhkan macOS." >&2
  exit 1
fi

find_python
if [ -z "$PYTHON" ]; then
  /usr/bin/osascript -e 'display dialog "CABEPEDES membutuhkan Python 3. Pasang Python 3 satu kali, lalu buka CABEPEDES.app kembali." buttons {"OK"} default button "OK" with title "CABEPEDES"' >/dev/null 2>&1 || true
  exit 1
fi

mkdir -p "$INSTALL_PARENT" "$PLIST_DIR"

UID_NOW="$(id -u)"
DOMAIN="gui/$UID_NOW"

# Stop the current managed instance before replacing an installed code copy.
# This makes repeated installs safe while preserving mutable application state.
launchctl bootout "$DOMAIN/$LABEL" >/dev/null 2>&1 || true

# First install or upgrade: copy the release into a user-writable permanent location.
# Existing mutable state is carried forward; executable/static release assets come from
# the new source package. This prevents old installed code from masking a fixed release.
if [ "$SOURCE_DIR" != "$INSTALL_DIR" ]; then
  TMP_DIR="$INSTALL_PARENT/.CABEPEDES.install.$$"
  rm -rf "$TMP_DIR"
  mkdir -p "$TMP_DIR"
  /usr/bin/ditto "$SOURCE_DIR/" "$TMP_DIR/"
  rm -rf "$TMP_DIR/.tls" "$TMP_DIR/__MACOSX" "$TMP_DIR/.DS_Store" "$TMP_DIR/__pycache__"

  if [ -d "$INSTALL_DIR" ]; then
    for MUTABLE in seceng.txt visitor.txt data-register.json notifications.json; do
      if [ -f "$INSTALL_DIR/$MUTABLE" ]; then
        cp -p "$INSTALL_DIR/$MUTABLE" "$TMP_DIR/$MUTABLE"
      fi
    done
    if [ -d "$INSTALL_DIR/log" ]; then /usr/bin/ditto "$INSTALL_DIR/log" "$TMP_DIR/log"; fi
    if [ -d "$INSTALL_DIR/.tls" ]; then /usr/bin/ditto "$INSTALL_DIR/.tls" "$TMP_DIR/.tls"; fi
  fi

  rm -rf "$INSTALL_DIR"
  mv "$TMP_DIR" "$INSTALL_DIR"
fi

sync_credential_from_source() {
  NAME="$1"
  SRC="$SOURCE_DIR/$NAME"
  DST="$INSTALL_DIR/$NAME"
  [ "$SOURCE_DIR" != "$INSTALL_DIR" ] || return 0
  [ -f "$SRC" ] || return 0
  if [ ! -f "$DST" ] || [ "$SRC" -nt "$DST" ]; then
    /bin/cp -p "$SRC" "$DST"
    echo "CABEPEDES credential synchronized: $NAME"
  fi
}

# Credential files are mutable operator state. When an operator edits the extracted
# release package and reruns the installer, carry the newer credential file into the
# permanent service location. Existing installed edits are preserved when they are newer.
sync_credential_from_source seceng.txt
sync_credential_from_source visitor.txt

printf 'CABEPEDES_USER_INSTALL=1\nCABEPEDES_RELEASE=1.3.2\n' > "$INSTALL_DIR/.cabepedes-install-marker"
chmod 700 "$INSTALL_DIR" 2>/dev/null || true
chmod +x "$INSTALL_DIR"/*.sh "$INSTALL_DIR"/*.command "$INSTALL_DIR/CABEPEDES.app/Contents/MacOS/CABEPEDES" 2>/dev/null || true

if [ ! -f "$INSTALL_DIR/server.py" ]; then
  echo "CABEPEDES installation tidak lengkap: server.py tidak ditemukan di $INSTALL_DIR" >&2
  exit 1
fi

# Transparansi audit: ketika release dijalankan dari hasil extract, arahkan file log
# yang terlihat di source package ke log runtime permanen. Manifest integrity tidak
# mencakup log/ karena log adalah mutable runtime state.
if [ "$SOURCE_DIR" != "$INSTALL_DIR" ]; then
  mkdir -p "$SOURCE_DIR/log" >/dev/null 2>&1 || true
  if [ -d "$SOURCE_DIR/log" ] && [ -d "$INSTALL_DIR/log" ]; then
    rm -f "$SOURCE_DIR/log/security-audit.log" >/dev/null 2>&1 || true
    ln -s "$INSTALL_DIR/log/security-audit.log" "$SOURCE_DIR/log/security-audit.log" >/dev/null 2>&1 || true
  fi
fi

APP_DIR_XML="$(xml_escape "$INSTALL_DIR")"
LOG_DIR="$HOME/Library/Logs/CABEPEDES"
mkdir -p "$LOG_DIR"
chmod 700 "$LOG_DIR" 2>/dev/null || true
LOG_DIR_XML="$(xml_escape "$LOG_DIR")"

# Recreate the LaunchAgent safely; it is independent of the originating terminal.
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$LABEL</string>
<key>ProgramArguments</key><array><string>/bin/sh</string><string>$APP_DIR_XML/server-launcher.sh</string></array>
<key>WorkingDirectory</key><string>$APP_DIR_XML</string>
<key>EnvironmentVariables</key><dict><key>CABEPEDES_NO_OPEN</key><string>1</string><key>CABEPEDES_LOCAL_PORT</key><string>1500</string><key>CABEPEDES_TLS_PORT</key><string>1501</string></dict>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ThrottleInterval</key><integer>5</integer>
<key>Umask</key><integer>63</integer>
<key>ProcessType</key><string>Background</string>
<key>StandardOutPath</key><string>$LOG_DIR_XML/server.out.log</string>
<key>StandardErrorPath</key><string>$LOG_DIR_XML/server.err.log</string>
</dict></plist>
EOF
chmod 600 "$PLIST"

if ! launchctl bootstrap "$DOMAIN" "$PLIST" >/dev/null 2>&1; then
  launchctl load -w "$PLIST" >/dev/null 2>&1 || {
    /usr/bin/osascript -e 'display dialog "CABEPEDES gagal mendaftarkan background service. Periksa LaunchAgents dan izin akun pengguna." buttons {"OK"} default button "OK" with title "CABEPEDES"' >/dev/null 2>&1 || true
    exit 1
  }
fi
launchctl enable "$DOMAIN/$LABEL" >/dev/null 2>&1 || true
launchctl kickstart -k "$DOMAIN/$LABEL" >/dev/null 2>&1 || true

for _ in 1 2 3 4 5 6 7 8 9 10; do
  if /usr/bin/curl -fsS --max-time 1 http://127.0.0.1:1500/healthz >/dev/null 2>&1; then
    /usr/bin/open "http://localhost:1500/" >/dev/null 2>&1 || true
    exit 0
  fi
  sleep 0.5
done

/usr/bin/osascript -e 'display dialog "CABEPEDES belum berhasil aktif. Periksa ~/Library/Logs/CABEPEDES/server.err.log." buttons {"OK"} default button "OK" with title "CABEPEDES"' >/dev/null 2>&1 || true
exit 1
