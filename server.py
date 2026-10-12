#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import fcntl
import shutil
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen

BASE_DIR = Path(__file__).resolve().parent
HOST = "0.0.0.0"
APP_VERSION = "1.3.2"
LOCAL_PORT = int(os.environ.get("CABEPEDES_LOCAL_PORT", "1500"))
TLS_PORT = int(os.environ.get("CABEPEDES_TLS_PORT", "1501"))
HTTP_BIND_HOST = "0.0.0.0"
TLS_BIND_HOST = "0.0.0.0"
LOCAL_OPEN_URL = f"http://localhost:{LOCAL_PORT}/"

DATA_FILE = BASE_DIR / "data-register.json"
BASELINE_FILE = BASE_DIR / "seed-baseline.json"
SECENG_FILE = BASE_DIR / "seceng.txt"
VISITOR_FILE = BASE_DIR / "visitor.txt"
LOG_DIR = BASE_DIR / "log"
LEGACY_LOG_DIR = BASE_DIR / "logs"
AUDIT_LOG = LOG_DIR / "security-audit.log"
AUDIT_FALLBACK_DIR = Path.home() / "Library" / "Logs" / "CABEPEDES"
AUDIT_FALLBACK_LOG = AUDIT_FALLBACK_DIR / "security-audit.log"
AUDIT_ERROR_COUNT = 0
AUDIT_MAX_VIEW_ROWS = 1000
NOTIFICATIONS_FILE = BASE_DIR / "notifications.json"
NOTIFICATIONS_BACKUP = BASE_DIR / "notifications.json.bak"
INSTANCE_LOCK_FILE = BASE_DIR / ".cabepedes.lock"
TLS_DIR = BASE_DIR / ".tls"
CERT_FILE = TLS_DIR / "cert.pem"
KEY_FILE = TLS_DIR / "key.pem"
CERT_META = TLS_DIR / "cert-meta.json"
TLS_CONFIG = TLS_DIR / "openssl.cnf"

MAX_BODY = 512 * 1024
MAX_RECORD_TEXT = 8000
MAX_NOTIFICATIONS = 500
SESSION_IDLE = {"Security Engineer": 8 * 3600, "Visitor": 2 * 3600}
REQUEST_LIMIT = 180
REQUEST_WINDOW = 60
NOTIFICATION_POLL_SECONDS = 15
USERNAME_RE_ENGINEER = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
USERNAME_RE_VISITOR = re.compile(r"^[A-Za-zÀ-ÖØ-öø-ÿ0-9 .,'’()/_-]{3,120}$")
SAFE_FIELD_RE = re.compile(r"^[^\r\n]{0,8000}$")

STATIC_ALLOWLIST = {
    "index.html": "text/html; charset=utf-8",
    "styles.css": "text/css; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
    "logic.js": "text/javascript; charset=utf-8",
    "Logo Browser.png": "image/png",
    "Logo CabePedes.png": "image/png",
}
INTEGRITY_MANIFEST = BASE_DIR / "build-manifest.json"
# Immutable release assets only. Mutable local state is intentionally excluded from the
# startup gate: seceng.txt, visitor.txt, data-register.json, SOURCE_WORKBOOK.xlsx, .tls and log/
# may legitimately change during normal operation without invalidating the executable release.
INTEGRITY_FILES = [
    "index.html", "styles.css", "app.js", "logic.js", "server.py",
    "run.sh", "start.command", "install.command", "bootstrap.sh", "server-launcher.sh",
    "CABEPEDES.app/Contents/Info.plist",
    "CABEPEDES.app/Contents/MacOS/CABEPEDES",
    "Logo Browser.png", "Logo CabePedes.png", "seed-baseline.json",
    "formula-spec.json", "security-frameworks.json"
]
SENSITIVE_NAMES = {
    "seceng.txt", "visitor.txt", "seed-baseline.json", "data-register.json",
    "seed-data.js", "SOURCE_WORKBOOK.xlsx", "formula-spec.json", "server.py",
    "verify_release.py", "security-audit.log", "SOURCE_SHA256.txt", "~$SOURCE_WORKBOOK.xlsx",
}

LOCK = threading.RLock()
DATA_LOCK = threading.RLock()
SESSIONS: dict[str, dict] = {}
CLIENTS: dict[str, dict] = {}
RATE_BUCKETS: dict[str, deque] = defaultdict(deque)
FAIL_COUNTS: dict[str, deque] = defaultdict(deque)
AUDIT_EVENT_BUCKETS: dict[str, deque] = defaultdict(deque)
AUDIT_LOCK = threading.RLock()
REQUEST_BUCKETS: dict[str, deque] = defaultdict(deque)
ACTIVE_VIEW_AUDIT_TS: dict[str, float] = {}
SECURITY_STATE: dict[str, str] = {}
NOTIFICATION_LOCK = threading.RLock()


def now_ts() -> float:
    return time.time()


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def user_hash(username: str) -> str:
    return hashlib.sha256(username.encode("utf-8", "ignore")).hexdigest()[:16]


def clean_text(value, max_len=8000) -> str:
    s = "" if value is None else str(value)
    if len(s) > max_len or any((ord(ch) < 32 and ch not in "\r\n\t") for ch in s):
        raise ValueError("Invalid text field")
    return s


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def normalize_record(record: dict) -> dict:
    headers = [
        'ID Issue','Tanggal Temuan','Aplikasi / Sistem','Jenis Insiden','Deskripsi','Domain Kontrol','Severity',
        'Faktor Penyebab','Remediasi','PIC','Target Selesai Pentest','Status Kerentanan','Tanggal Selesai Remediasi',
        'Notifikasi','Status Rilis','Keterangan'
    ]
    if not isinstance(record, dict):
        raise ValueError("Record must be an object")
    out = {}
    for h in headers:
        v = record.get(h, "")
        if v is None:
            v = ""
        out[h] = clean_text(v)
    return out


def validate_records(records):
    if not isinstance(records, list) or len(records) > 10000:
        raise ValueError("Invalid record collection")
    out = []
    ids = set()
    for r in records:
        nr = normalize_record(r)
        rid = nr['ID Issue']
        if not rid:
            raise ValueError("ID Issue is required")
        if rid in ids:
            raise ValueError("Duplicate ID Issue")
        ids.add(rid)
        if nr['Severity'] and len(nr['Severity']) > 30:
            raise ValueError("Invalid severity")
        out.append(nr)
    return out

ISSUE_ID_RE = re.compile(r"^VA-(\d{4})-(\d{3})$")
VALID_SEVERITIES = {"High", "Medium", "Low", "Info", "Warning"}
VALID_STATUS = {"Open", "Close"}
DATE_FIELDS = {"Tanggal Temuan", "Target Selesai Pentest", "Tanggal Selesai Remediasi"}

def validate_business_record(record: dict, *, allow_blank_id=False) -> dict:
    nr = normalize_record(record)
    rid = nr["ID Issue"]
    if not allow_blank_id:
        if not ISSUE_ID_RE.fullmatch(rid):
            raise ValueError("Invalid ID Issue format")
    elif rid:
        raise ValueError("ID Issue is server-managed")
    if nr["Severity"] not in VALID_SEVERITIES:
        raise ValueError("Invalid severity")
    if nr["Status Kerentanan"] not in VALID_STATUS:
        raise ValueError("Invalid vulnerability status")
    for field in DATE_FIELDS:
        value = nr[field].strip()
        if value and value != "-" and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            raise ValueError(f"Invalid date field: {field}")
    if len(nr["Aplikasi / Sistem"]) > 500 or len(nr["PIC"]) > 300:
        raise ValueError("Field too long")
    return nr

def next_issue_id(records: list[dict], year: int | None = None) -> str:
    yyyy = int(year or datetime.now().astimezone().year)
    max_seq = 0
    for record in records:
        rid = record.get("ID Issue", "")
        match = ISSUE_ID_RE.fullmatch(rid)
        if match and int(match.group(1)) == yyyy:
            max_seq = max(max_seq, int(match.group(2)))
    if max_seq >= 999:
        raise ValueError("ID Issue sequence exhausted for current year")
    return f"VA-{yyyy:04d}-{max_seq + 1:03d}"


def atomic_write_json(path: Path, data) -> None:
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    raw = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        if path.exists():
            backup = path.with_name(path.name + ".bak")
            try:
                shutil.copy2(path, backup)
                os.chmod(backup, 0o600)
            except OSError:
                pass
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        raise


def _quarantine(path: Path) -> None:
    if not path.exists():
        return
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = path.with_name(f"{path.name}.corrupt-{stamp}")
    try:
        shutil.move(str(path), str(target))
        os.chmod(target, 0o600)
        audit("data_quarantined", result="deny", detail=target.name[:120])
    except OSError:
        pass


def _load_valid_records(path: Path):
    return validate_records(load_json(path))


def load_records() -> list[dict]:
    if not DATA_FILE.exists():
        baseline = validate_records(load_json(BASELINE_FILE))
        atomic_write_json(DATA_FILE, baseline)
        return baseline
    try:
        return _load_valid_records(DATA_FILE)
    except Exception as primary_exc:
        backup = DATA_FILE.with_name(DATA_FILE.name + ".bak")
        if backup.exists():
            try:
                records = _load_valid_records(backup)
                atomic_write_json(DATA_FILE, records)
                audit("data_restore_backup", result="success", detail=type(primary_exc).__name__)
                return records
            except Exception:
                pass
        _quarantine(DATA_FILE)
        baseline = validate_records(load_json(BASELINE_FILE))
        atomic_write_json(DATA_FILE, baseline)
        audit("data_restore_baseline", result="deny", detail="no valid backup available")
        return baseline


def available_lan_ips() -> list[str]:
    candidates = []
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
        candidates.extend([i[4][0] for i in infos])
    except OSError:
        pass
    for ip in candidates:
        try:
            obj = ipaddress.ip_address(ip)
            if obj.is_private and not obj.is_loopback:
                pass
            else:
                continue
            if ip not in candidates:
                candidates.append(ip)
        except ValueError:
            continue
    # macOS commonly exposes LAN addresses through getifaddrs only; use ifconfig as a read-only fallback.
    try:
        proc = subprocess.run(["/sbin/ifconfig"], capture_output=True, text=True, timeout=2, check=False)
        for ip in re.findall(r"\binet (\d+\.\d+\.\d+\.\d+)", proc.stdout):
            try:
                obj = ipaddress.ip_address(ip)
                if obj.is_private and not obj.is_loopback and ip not in candidates:
                    candidates.append(ip)
            except ValueError:
                continue
    except Exception:
        pass
    return list(dict.fromkeys(x for x in candidates if x not in {"127.0.0.1", "0.0.0.0"}))


def ensure_tls() -> bool:
    TLS_DIR.mkdir(exist_ok=True)
    try:
        os.chmod(TLS_DIR, 0o700)
    except OSError:
        pass
    ips = available_lan_ips()
    hostnames = ["localhost", socket.gethostname()]
    try:
        localhost_name = subprocess.check_output(["/usr/sbin/scutil", "--get", "LocalHostName"], text=True, timeout=2).strip()
        if localhost_name:
            hostnames.append(localhost_name + ".local")
    except Exception:
        pass
    hostnames = list(dict.fromkeys([h for h in hostnames if h]))
    wanted_meta = {"ips": sorted(ips), "hostnames": sorted(hostnames)}
    current_meta = None
    try:
        current_meta = json.loads(CERT_META.read_text(encoding="utf-8"))
    except Exception:
        pass
    if CERT_FILE.exists() and KEY_FILE.exists() and current_meta == wanted_meta:
        return True

    if not shutil_which("openssl"):
        audit("tls_unavailable", detail="openssl not found; LAN HTTPS disabled")
        return False

    sans = [f"DNS:{h}" for h in hostnames]
    sans += [f"IP:{ip}" for ip in ips]
    sans.append("IP:127.0.0.1")
    san_text = ",".join(sans)
    cn = hostnames[1] if len(hostnames) > 1 else "CABEPEDES"
    config = f"""[req]\ndistinguished_name=req_dn\nx509_extensions=v3_req\nprompt=no\n[req_dn]\nCN={cn}\n[v3_req]\nsubjectAltName={san_text}\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"""
    TLS_CONFIG.write_text(config, encoding="utf-8")
    try:
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "825", "-nodes",
            "-keyout", str(KEY_FILE), "-out", str(CERT_FILE), "-config", str(TLS_CONFIG)
        ], capture_output=True, text=True, timeout=20, check=True)
        CERT_META.write_text(json.dumps(wanted_meta, indent=2), encoding="utf-8")
        os.chmod(KEY_FILE, 0o600)
        os.chmod(CERT_FILE, 0o644)
        os.chmod(CERT_META, 0o600)
        try:
            TLS_CONFIG.unlink()
        except OSError:
            pass
        return True
    except Exception as exc:
        audit("tls_generation_failed", detail=type(exc).__name__)
        return False


def shutil_which(name: str):
    for path in os.environ.get("PATH", "").split(os.pathsep):
        cand = Path(path) / name
        if cand.exists() and os.access(cand, os.X_OK):
            return str(cand)
    return None


CREDENTIAL_LINE_RE = re.compile(r"^(username|password)\s*:\s*(.*?)\s*$", re.IGNORECASE)

def parse_credentials(path: Path, visitor=False):
    """Load credential allowlists fresh from disk on every login.

    Supported format is intentionally simple and operator-editable:
      Username: alice
      Password: pbkdf2_sha256$...

    Leading/trailing whitespace, UTF-8 BOM, blank lines and comments are ignored.
    For Security Engineer accounts, a Password line must immediately follow its
    Username block; malformed hashes are ignored rather than creating a login path.
    Duplicate usernames are case-insensitively de-duplicated, with the last valid
    occurrence winning. Visitor entries are username-only.
    """
    result = {}
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeError):
        return result

    pending_username = None
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = CREDENTIAL_LINE_RE.fullmatch(line)
        if not match:
            continue
        field = match.group(1).casefold()
        value = match.group(2).strip()

        if field == "username":
            if not value or not validate_username("Visitor" if visitor else "Security Engineer", value):
                pending_username = None
                continue
            pending_username = value
            if visitor:
                result[value.casefold()] = value
            continue

        # password: only applies to the immediately preceding valid username.
        if visitor or not pending_username:
            continue
        encoded = value
        if re.fullmatch(r"pbkdf2_sha256\$600000\$[0-9a-fA-F]{32}\$[0-9a-fA-F]{64}", encoded, re.IGNORECASE):
            result[pending_username.casefold()] = (pending_username, encoded.lower())
        pending_username = None

    return result


PBKDF2_ALG = "sha256"
PBKDF2_ITERATIONS = 600_000
PBKDF2_SALT_BYTES = 16

def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, iterations, salt_hex, digest_hex = encoded.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        count = int(iterations)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        if count < 600_000 or count > 2_000_000 or len(salt) < 16 or len(expected) != 32:
            return False
        derived = hashlib.pbkdf2_hmac(PBKDF2_ALG, password.encode("utf-8"), salt, count, dklen=32)
        return secrets.compare_digest(derived, expected)
    except (ValueError, TypeError):
        return False


def credential_file_is_hardened(path: Path) -> bool:
    try:
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]
        passwords = [line.split(":", 1)[1].strip() for line in lines if line.lower().startswith("password:")]
        return bool(passwords) and all(
            re.fullmatch(r"pbkdf2_sha256\$600000\$[0-9a-f]{32}\$[0-9a-f]{64}", encoded)
            for encoded in passwords
        )
    except Exception:
        return False

def validate_username(role: str, username: str) -> bool:
    if role == "Security Engineer":
        return bool(USERNAME_RE_ENGINEER.fullmatch(username))
    if role == "Visitor":
        return bool(USERNAME_RE_VISITOR.fullmatch(username))
    return False


def rate_allowed(ip: str) -> bool:
    cutoff = now_ts() - 300
    bucket = RATE_BUCKETS[ip]
    while bucket and bucket[0] < cutoff:
        bucket.popleft()
    if len(bucket) >= 8:
        return False
    bucket.append(now_ts())
    return True


def record_failed_auth(ip: str) -> None:
    cutoff = now_ts() - 600
    dq = FAIL_COUNTS[ip]
    while dq and dq[0] < cutoff:
        dq.popleft()
    dq.append(now_ts())
    if len(dq) in {5, 8, 12}:
        audit("security_alert", ip=ip, detail="repeated authentication failures")


def clear_failed_auth(ip: str) -> None:
    FAIL_COUNTS.pop(ip, None)


def request_allowed(ip: str) -> bool:
    now = now_ts()
    bucket = REQUEST_BUCKETS[ip]
    while bucket and bucket[0] < now - REQUEST_WINDOW:
        bucket.popleft()
    if len(bucket) >= REQUEST_LIMIT:
        return False
    bucket.append(now)
    return True


AUDIT_COLUMNS = ["Timestamp","Event","Role","Username","IP","Device","Type","Location","OS","Browser","Session","Result","Detail"]
AUDIT_HEADER = "| " + " | ".join(AUDIT_COLUMNS) + " |\n" + "|" + "|".join("---" for _ in AUDIT_COLUMNS) + "|\n"

def redact_sensitive_detail(value: str) -> str:
    s = "" if value is None else str(value)
    # Never persist credentials, bearer tokens, cookies or hashes in the operational log.
    s = re.sub(r"(?i)(password|passwd|pwd|secret|token|csrf|cookie)\s*[:=]\s*[^,;\s]+", r"\1=[REDACTED]", s)
    s = re.sub(r"(?i)authorization\s*[:=]\s*[^,;\s]+", "authorization=[REDACTED]", s)
    s = re.sub(r"(?i)(pbkdf2_sha256\$)[^\s,;]+", r"\1[REDACTED]", s)
    return s


def _audit_cell(value, max_len=220):
    s = redact_sensitive_detail(value)
    s = s.replace("|", "¦").replace("\r", " ").replace("\n", " ").strip()
    return s[:max_len]


def _audit_prepare(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    if not path.exists() or path.stat().st_size == 0:
        path.write_text(AUDIT_HEADER, encoding="utf-8")
    else:
        # Repair a damaged/legacy header without deleting historical rows.
        try:
            with path.open("r", encoding="utf-8") as fh:
                first = fh.readline().strip()
            expected = AUDIT_HEADER.splitlines()[0].strip()
            if first != expected:
                existing = path.read_text(encoding="utf-8")
                if existing.startswith("| Timestamp"):
                    first_newline = existing.find("\n")
                    existing = existing[first_newline + 1:] if first_newline >= 0 else ""
                path.write_text(AUDIT_HEADER + existing, encoding="utf-8")
        except OSError:
            raise
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def ensure_audit_log() -> None:
    """Ensure the primary runtime audit trail exists and is writable."""
    with AUDIT_LOCK:
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            _audit_prepare(AUDIT_LOG)
            return
        except OSError:
            # Installed CABEPEDES normally uses the primary per-application path.
            # If the path is unexpectedly unavailable, retain a user-scoped fallback so
            # security events are not silently lost.
            AUDIT_FALLBACK_DIR.mkdir(parents=True, exist_ok=True)
            _audit_prepare(AUDIT_FALLBACK_LOG)


def _audit_target() -> Path:
    """Kembalikan lokasi log audit yang dapat digunakan oleh server."""
    try:
        _audit_prepare(AUDIT_LOG)
        return AUDIT_LOG
    except OSError:
        _audit_prepare(AUDIT_FALLBACK_LOG)
        return AUDIT_FALLBACK_LOG


def _audit_rows(limit: int = AUDIT_MAX_VIEW_ROWS) -> tuple[Path, list[list[str]]]:
    """Baca baris audit terakhir dari lokasi runtime yang aktif."""
    target = _audit_target()
    limit = max(1, min(int(limit), AUDIT_MAX_VIEW_ROWS))
    try:
        lines = target.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        lines = []
    rows = []
    expected_cells = len(AUDIT_COLUMNS)
    for line in lines:
        if not line.startswith("|") or line.startswith("|---"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != expected_cells or cells == AUDIT_COLUMNS:
            continue
        rows.append(cells)
    return target, rows[-limit:]


def audit(event: str, *, ip="", username="", role="", result="", detail="", client=None, location="", session="") -> None:
    """Append exactly one normalized audit event. Failures are surfaced diagnostically and never crash the request path."""
    global AUDIT_ERROR_COUNT
    try:
        c = client or {}
        if not isinstance(c, dict):
            c = {}
        loc = location or (
            f"{float(c.get('latitude')):.6f}, {float(c.get('longitude')):.6f} ±{float(c.get('accuracy', 0)):.0f}m"
            if c.get('latitude') is not None and c.get('longitude') is not None else c.get('location_status', "")
        )
        sess = session or c.get("session", "")
        values = [
            now_iso(), _audit_cell(event, 80), _audit_cell(role or c.get("role", "")),
            _audit_cell(username or c.get("username", "")), _audit_cell(ip or c.get("ip", "")),
            _audit_cell(c.get("device_name", "")), _audit_cell(c.get("device_type", "")), _audit_cell(loc),
            _audit_cell(c.get("os", "")), _audit_cell(c.get("browser", "")), _audit_cell(sess, 80),
            _audit_cell(result, 40), _audit_cell(detail)
        ]
        row = "| " + " | ".join(values) + " |\n"
        with AUDIT_LOCK:
            target = _audit_target()
            with target.open("a", encoding="utf-8") as fh:
                fh.write(row)
                fh.flush()
            try:
                os.chmod(target, 0o600)
            except OSError:
                pass
            # Rotate only the primary operational file; the header is recreated atomically.
            if target == AUDIT_LOG and target.stat().st_size > 4 * 1024 * 1024:
                rotated = LOG_DIR / "security-audit.log.1"
                try:
                    if rotated.exists():
                        rotated.unlink()
                    target.replace(rotated)
                    _audit_prepare(AUDIT_LOG)
                except OSError:
                    pass
    except Exception as exc:
        AUDIT_ERROR_COUNT += 1
        try:
            print(f"CABEPEDES audit write failed: {type(exc).__name__}", file=sys.stderr)
        except Exception:
            pass

def audit_client_snapshot(event: str, info: dict, *, detail="", result="success") -> None:
    audit(event, username=info.get("username",""), role=info.get("role",""), ip=info.get("ip",""), result=result, detail=detail, client=info, session=info.get("session",""))

def parse_cookies(handler):
    cookie = SimpleCookie()
    raw = handler.headers.get("Cookie", "")
    if raw:
        try:
            cookie.load(raw)
        except Exception:
            pass
    return cookie


def secure_cookie_header(token: str, secure: bool, max_age: int) -> str:
    parts = [f"cabepedes_session={token}", "Path=/", "HttpOnly", "SameSite=Strict", f"Max-Age={int(max_age)}"]
    if secure:
        parts.insert(2, "Secure")
    return "; ".join(parts)


def csrf_cookie_header(token: str, secure: bool) -> str:
    parts = [f"cabepedes_csrf={token}", "Path=/", "SameSite=Strict", "Max-Age=28800"]
    if secure:
        parts.insert(2, "Secure")
    return "; ".join(parts)


def parse_session(handler):
    cookie = parse_cookies(handler)
    token = cookie.get("cabepedes_session")
    if not token:
        return None, None
    token = token.value
    with LOCK:
        sess = SESSIONS.get(token)
        if not sess:
            return None, None
        if sess["expires_at"] < now_ts() or sess["last_active"] + SESSION_IDLE.get(sess["role"], 3600) < now_ts():
            SESSIONS.pop(token, None)
            CLIENTS.pop(token, None)
            return None, None
        sess["last_active"] = now_ts()
        client = CLIENTS.get(token)
        if client:
            client["last_active"] = sess["last_active"]
        return token, sess


def client_identity(handler, token=None, browser_info=None, geo=None):
    ip = handler.client_address[0] if handler.client_address else ""
    if token:
        with LOCK:
            sess = SESSIONS.get(token, {})
            username = sess.get("username", "")
            role = sess.get("role", "")
            short_session = hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
        info = CLIENTS.setdefault(token, {})
        info.update({
            "username": username,
            "role": role,
            "ip": ip,
            "last_active": now_ts(),
            "session": short_session,
        })
        if browser_info:
            info.update({k: clean_text(browser_info.get(k, ""), 120) for k in ["device_name", "device_type", "os", "browser"]})
        if geo:
            try:
                lat = float(geo.get("latitude")); lon = float(geo.get("longitude")); acc = float(geo.get("accuracy"))
                if -90 <= lat <= 90 and -180 <= lon <= 180 and 0 <= acc <= 1_000_000:
                    info.update({"latitude": round(lat, 6), "longitude": round(lon, 6), "accuracy": acc, "location_status": "granted"})
            except (TypeError, ValueError):
                pass
        return dict(info)
    return {"ip": ip}


def audit_client_if_changed(token: str, info: dict, reason: str) -> None:
    fingerprint_payload = {k: info.get(k, "") for k in ["username","role","ip","device_name","device_type","os","browser","latitude","longitude","accuracy","location_status"]}
    fingerprint = hashlib.sha256(json.dumps(fingerprint_payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
    with LOCK:
        prev = CLIENTS.get(token, {}).get("audit_fingerprint")
        CLIENTS.setdefault(token, {})["audit_fingerprint"] = fingerprint
    if prev != fingerprint:
        audit_client_snapshot("client_presence", info, detail=reason)


def rate_audit_event(token: str) -> bool:
    now = now_ts()
    bucket = AUDIT_EVENT_BUCKETS[token]
    while bucket and bucket[0] < now - 10:
        bucket.popleft()
    if len(bucket) >= 120:
        return False
    bucket.append(now)
    return True


def require_csrf(handler, sess):
    token = handler.headers.get("X-CSRF-Token", "")
    if not token or not secrets.compare_digest(token, sess.get("csrf", "")):
        audit("csrf_denied", ip=handler.client_address[0], username=sess.get("username", ""), role=sess.get("role", ""), result="deny")
        return False
    return True


def require_engineer(handler):
    _, sess = parse_session(handler)
    if not sess or sess.get("role") != "Security Engineer":
        audit("access_denied", ip=handler.client_address[0], username=(sess or {}).get("username", ""), role=(sess or {}).get("role", ""), result="deny", detail="engineer required")
        return None
    return sess


def json_bytes(payload) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def is_loopback_client(handler) -> bool:
    try:
        return ipaddress.ip_address(handler.client_address[0]).is_loopback
    except ValueError:
        return False


def request_host(handler) -> str:
    raw = (handler.headers.get("Host") or "").strip()
    if not raw:
        return ""
    if raw.startswith("[") and "]" in raw:
        return raw[1:raw.index("]")].lower()
    return raw.rsplit(":", 1)[0].lower() if ":" in raw else raw.lower()


def safe_lan_host(handler) -> str:
    host = request_host(handler)
    allowed = allowed_hostnames()
    if host in allowed and host not in {"localhost", "127.0.0.1"}:
        return host
    try:
        obj = ipaddress.ip_address(host)
        if obj.version == 4 and (obj.is_private or obj.is_loopback):
            return host
    except ValueError:
        pass
    ips = available_lan_ips()
    return ips[0] if ips else "localhost"


def enforce_lan_tls(handler) -> bool:
    if handler.secure or is_loopback_client(handler):
        return True
    if not (CERT_FILE.exists() and KEY_FILE.exists()):
        handler.send_json({"error": "LAN HTTPS belum tersedia pada server CABEPEDES."}, 503)
        return False
    parsed = urlparse(handler.path)
    location = f"https://{safe_lan_host(handler)}:{TLS_PORT}{parsed.path or '/'}"
    if parsed.query:
        location += "?" + parsed.query
    handler.redirect(location, 307)
    return False


def infer_network(request_secure: bool) -> dict:
    ips = available_lan_ips()
    return {
        "local_url": LOCAL_OPEN_URL,
        "lan_http_urls": [f"http://{ip}:{LOCAL_PORT}/" for ip in ips],
        "lan_urls": [f"https://{ip}:{TLS_PORT}/" for ip in ips],
        "https_enabled": bool(CERT_FILE.exists() and KEY_FILE.exists()),
        "host_name": socket.gethostname(),
    }


SECURITY_CHECKS = {
    "OWASP Top 10:2025": [
        ("A01 Broken Access Control", "Server-side role checks, deny-by-default routes, static allowlist"),
        ("A02 Security Misconfiguration", "Security headers, TLS minimum, strict file permissions"),
        ("A03 Software Supply Chain Failures", "No CDN/runtime dependency, local assets, SHA-256 manifest"),
        ("A04 Cryptographic Failures", "PBKDF2-HMAC-SHA256 salted password verification, secure tokens, TLS"),
        ("A05 Injection", "Strict content-type, body limits, field validation, HTML escaping"),
        ("A06 Insecure Design", "RBAC by design, same-origin API, atomic persistence"),
        ("A07 Authentication Failures", "Rate limit, session idle timeout, CSRF and secure cookies"),
        ("A08 Software or Data Integrity Failures", "SHA-256 integrity manifest, validated records, atomic writes"),
        ("A09 Security Logging and Alerting Failures", "Append-only table log, login/RBAC/CRUD/client/menu events, alert hooks"),
        ("A10 Mishandling of Exceptional Conditions", "Generic error responses, defensive parsing, bounded requests"),
    ],
    "OWASP ASVS 5.0": [
        ("V1 Architecture / V2 Authentication", "Session, authentication, input validation and trusted boundaries"),
        ("V3 Session Management", "Idle timeout, random session IDs, logout invalidation, secure cookies"),
        ("V4 Access Control", "Role enforcement on every protected API"),
        ("V5 Validation / V6 Stored Cryptography", "Bounded input and salted PBKDF2 password verification"),
        ("V7 Error Handling / V9 Communication", "Safe error messages, HTTPS for LAN, security headers"),
        ("V10 Malicious Code / V11 Business Logic / V13 API", "Static asset allowlist, workflow checks, same-origin JSON API"),
    ],
    "OWASP WSTG v4.2": [
        ("WSTG-CONF", "Configuration and deployment checks"),
        ("WSTG-IDNT / AUTHN / AUTHZ", "Identity, authentication and authorization checks"),
        ("WSTG-SESS", "Session management checks"),
        ("WSTG-INPV", "Input validation checks"),
        ("WSTG-ERRH / CLNT", "Error handling and client-side security controls"),
    ],
}


def run_security_self_check() -> dict:
    checks = {}
    checks["credential_hashing"] = credential_file_is_hardened(SECENG_FILE)
    checks["credential_permissions"] = bool(SECENG_FILE.exists() and (SECENG_FILE.stat().st_mode & 0o077) == 0)
    checks["visitor_permissions"] = bool(VISITOR_FILE.exists() and (VISITOR_FILE.stat().st_mode & 0o077) == 0)
    checks["data_permissions"] = bool(DATA_FILE.exists() and (DATA_FILE.stat().st_mode & 0o077) == 0)
    checks["baseline_permissions"] = bool(BASELINE_FILE.exists() and (BASELINE_FILE.stat().st_mode & 0o077) == 0)
    checks["audit_log_permissions"] = False
    checks["audit_log_schema"] = False
    try:
        target = _audit_target()
        checks["audit_log_permissions"] = bool(target.exists() and (target.stat().st_mode & 0o077) == 0)
        first = target.read_text(encoding="utf-8").splitlines()[0].strip()
        checks["audit_log_schema"] = first == AUDIT_HEADER.splitlines()[0].strip()
    except Exception:
        checks["audit_log_permissions"] = False
        checks["audit_log_schema"] = False
    checks["tls_files"] = (CERT_FILE.exists() and KEY_FILE.exists())
    integrity_ok, _ = integrity_status()
    checks["integrity_assets"] = integrity_ok
    checks["data_schema"] = True
    try:
        validate_records(load_json(DATA_FILE))
    except Exception:
        checks["data_schema"] = False
    checks["static_allowlist"] = all(k in STATIC_ALLOWLIST for k in {"index.html","styles.css","app.js","logic.js","Logo Browser.png","Logo CabePedes.png"})
    status = "PASS" if all(checks.values()) else "WARN"
    signature = json.dumps(checks, sort_keys=True)
    if SECURITY_STATE.get("self_check") != signature:
        SECURITY_STATE["self_check"] = signature
        audit("security_self_check", result=status, detail=", ".join(f"{k}={'PASS' if v else 'WARN'}" for k,v in checks.items()))
    return {"status": status, "checks": checks, "frameworks": SECURITY_CHECKS}


def account_keys_for_role(role: str) -> list[str]:
    path = SECENG_FILE if role == "Security Engineer" else VISITOR_FILE
    users = parse_credentials(path, visitor=(role == "Visitor"))
    return sorted(users.keys())


def notification_key(role: str, username: str) -> str:
    return f"{role}:{username.casefold()}"


def load_notifications() -> list[dict]:
    with NOTIFICATION_LOCK:
        if not NOTIFICATIONS_FILE.exists():
            return []
        try:
            raw = load_json(NOTIFICATIONS_FILE)
            items = raw.get("notifications", []) if isinstance(raw, dict) else []
            if not isinstance(items, list):
                raise ValueError("notifications schema")
            clean = []
            for item in items[-MAX_NOTIFICATIONS:]:
                if not isinstance(item, dict):
                    continue
                clean.append({
                    "id": clean_text(item.get("id", ""), 80),
                    "kind": clean_text(item.get("kind", ""), 30),
                    "created_at": clean_text(item.get("created_at", ""), 80),
                    "roles": [r for r in item.get("roles", []) if r in {"Security Engineer", "Visitor"}],
                    "actor_username": clean_text(item.get("actor_username", ""), 120),
                    "actor_role": clean_text(item.get("actor_role", ""), 40),
                    "issue_id": clean_text(item.get("issue_id", ""), 120),
                    "application": clean_text(item.get("application", ""), 500),
                    "pic": clean_text(item.get("pic", ""), 300),
                    "changed_fields": [clean_text(x, 120) for x in item.get("changed_fields", [])[:20]],
                    "read_by": [clean_text(x, 180) for x in item.get("read_by", [])[:500]],
                })
            return clean
        except Exception as exc:
            if NOTIFICATIONS_BACKUP.exists():
                try:
                    raw = load_json(NOTIFICATIONS_BACKUP)
                    items = raw.get("notifications", []) if isinstance(raw, dict) else []
                    if not isinstance(items, list):
                        raise ValueError("notification backup schema")
                    clean = []
                    for item in items[-MAX_NOTIFICATIONS:]:
                        if not isinstance(item, dict):
                            continue
                        clean.append({
                            "id": clean_text(item.get("id", ""), 80),
                            "kind": clean_text(item.get("kind", ""), 30),
                            "created_at": clean_text(item.get("created_at", ""), 80),
                            "roles": [r for r in item.get("roles", []) if r in {"Security Engineer", "Visitor"}],
                            "actor_username": clean_text(item.get("actor_username", ""), 120),
                            "actor_role": clean_text(item.get("actor_role", ""), 40),
                            "issue_id": clean_text(item.get("issue_id", ""), 120),
                            "application": clean_text(item.get("application", ""), 500),
                            "pic": clean_text(item.get("pic", ""), 300),
                            "changed_fields": [clean_text(x, 120) for x in item.get("changed_fields", [])[:20]],
                            "read_by": [clean_text(x, 180) for x in item.get("read_by", [])[:500]],
                        })
                    return clean
                except Exception:
                    pass
            _quarantine(NOTIFICATIONS_FILE)
            audit("notification_store_reset", result="deny", detail=type(exc).__name__)
            return []


def save_notifications(items: list[dict]) -> None:
    atomic_write_json(NOTIFICATIONS_FILE, {"version": 1, "notifications": items[-MAX_NOTIFICATIONS:]})


def create_notification(*, kind: str, roles: list[str], actor_username: str, actor_role: str, record: dict, changed_fields=None) -> None:
    item = {
        "id": "NTF-" + secrets.token_urlsafe(14),
        "kind": kind,
        "created_at": now_iso(),
        "roles": roles,
        "actor_username": actor_username,
        "actor_role": actor_role,
        "issue_id": record.get("ID Issue", ""),
        "application": record.get("Aplikasi / Sistem", ""),
        "pic": record.get("PIC", ""),
        "changed_fields": list(changed_fields or []),
        "read_by": [],
    }
    with NOTIFICATION_LOCK:
        items = load_notifications()
        items.append(item)
        save_notifications(items)


def notifications_for_user(role: str, username: str) -> dict:
    key = notification_key(role, username)
    items = load_notifications()
    visible = [item for item in items if role in item.get("roles", [])]
    visible = visible[-100:][::-1]
    unread = sum(1 for item in visible if key not in item.get("read_by", []))
    for item in visible:
        item["unread"] = key not in item.get("read_by", [])
    return {"notifications": visible, "unread_count": unread, "count": len(visible)}


def mark_notifications_read(role: str, username: str, ids: list[str], mark_all=False) -> dict:
    key = notification_key(role, username)
    with NOTIFICATION_LOCK:
        items = load_notifications()
        selected = set(ids[:100])
        for item in items:
            if role not in item.get("roles", []):
                continue
            if mark_all or item.get("id") in selected:
                rb = item.setdefault("read_by", [])
                if key not in rb:
                    rb.append(key)
                    if len(rb) > 500:
                        del rb[:-500]
        save_notifications(items)
    return {"ok": True}


def security_monitor() -> None:
    while True:
        try:
            now = now_ts()
            with LOCK:
                stale = [t for t,v in SESSIONS.items() if v.get("expires_at", 0) < now]
                for t in stale:
                    SESSIONS.pop(t, None); CLIENTS.pop(t, None); AUDIT_EVENT_BUCKETS.pop(t, None); ACTIVE_VIEW_AUDIT_TS.pop(t, None)
                stale_clients = [t for t,v in CLIENTS.items() if v.get("last_active", 0) + 300 < now]
                for t in stale_clients:
                    CLIENTS.pop(t, None)
            run_security_self_check()
        except Exception:
            pass
        time.sleep(60)


def allowed_hostnames() -> set[str]:
    values = {"localhost", "127.0.0.1", socket.gethostname().lower()}
    try:
        local_name = subprocess.check_output(["/usr/sbin/scutil", "--get", "LocalHostName"], text=True, timeout=2).strip()
        if local_name:
            values.add(local_name.lower())
            values.add((local_name + ".local").lower())
    except Exception:
        pass
    values.update(ip.lower() for ip in available_lan_ips())
    return values


def valid_request_host(handler) -> bool:
    host = request_host(handler)
    if not host:
        return False
    allowed = allowed_hostnames()
    return host in allowed


def instance_lock() -> object | None:
    fh = None
    try:
        INSTANCE_LOCK_FILE.touch(mode=0o600, exist_ok=True)
        os.chmod(INSTANCE_LOCK_FILE, 0o600)
        fh = INSTANCE_LOCK_FILE.open("r+")
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fh
    except (OSError, IOError):
        if fh is not None:
            try:
                fh.close()
            except OSError:
                pass
        return None


class Handler(BaseHTTPRequestHandler):
    server_version = "CABEPEDES/1.3.2"
    sys_version = ""

    def log_message(self, fmt, *args):
        return

    @property
    def secure(self):
        return isinstance(self.server, SecureHTTPServer)

    def headers_common(self, content_type="application/json; charset=utf-8", no_store=False):
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "geolocation=(self), camera=(), microphone=(), payment=(), usb=()")
        self.send_header("X-DNS-Prefetch-Control", "off")
        self.send_header("X-Permitted-Cross-Domain-Policies", "none")
        self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; manifest-src 'self'; upgrade-insecure-requests")
        if no_store:
            self.send_header("Cache-Control", "no-store")
        if self.secure:
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    def send_json(self, payload, status=200, extra_headers=None):
        body = json_bytes(payload)
        self.send_response(status)
        self.headers_common(no_store=True)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, text, status=200, content_type="text/plain; charset=utf-8", extra_headers=None):
        body = text.encode("utf-8")
        self.send_response(status)
        self.headers_common(content_type, no_store=False)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location, status=302):
        self.send_response(status)
        self.headers_common(no_store=True)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def read_body(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length < 0 or length > MAX_BODY:
            raise ValueError("Request body too large")
        return self.rfile.read(length)

    def parse_json_body(self):
        raw = self.read_body()
        if not raw:
            return {}
        ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if ctype != "application/json":
            raise ValueError("JSON required")
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Object required")
        return data

    def do_GET(self):
        if not valid_request_host(self):
            return self.send_json({"error": "Invalid Host header"}, 421)
        if not enforce_lan_tls(self):
            return
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        if path == "/" or path == "/index.html":
            token, sess = parse_session(self)
            if sess:
                info = client_identity(self, token)
                audit("dashboard_view", ip=self.client_address[0], username=sess["username"], role=sess["role"], result="success", detail="GET /", client=info, session=info.get("session", ""))
            else:
                audit("login_page_view", ip=self.client_address[0], result="success", detail="GET /")
            return self.static_file("index.html")
        if path == "/log/security-audit.log":
            token, sess = parse_session(self)
            if not sess:
                audit("access_denied", ip=self.client_address[0], result="deny", detail="unauthenticated audit log view")
                return self.send_json({"error": "Authentication required"}, 401)
            if sess.get("role") != "Security Engineer":
                audit("access_denied", ip=self.client_address[0], username=sess.get("username", ""), role=sess.get("role", ""), result="deny", detail="audit log requires Security Engineer")
                return self.send_json({"error": "Forbidden"}, 403)
            try:
                target = _audit_target()
                raw = target.read_text(encoding="utf-8")
                info = client_identity(self, token)
                self.audit_authenticated_activity(token, sess, event="audit_log_raw_view", detail="GET /log/security-audit.log", client=info)
                return self.send_text(raw, 200, "text/plain; charset=utf-8", {"Content-Disposition": 'inline; filename="security-audit.log"', "Cache-Control": "no-store"})
            except (OSError, UnicodeError):
                audit("audit_log_read_failed", ip=self.client_address[0], username=sess["username"], role=sess["role"], result="deny", detail="raw audit log read failed")
                return self.send_json({"error": "Log audit tidak dapat dibaca saat ini."}, 503)
        if path.startswith("/api/"):
            if not request_allowed(self.client_address[0]):
                return self.send_json({"error": "Too many requests"}, 429)
            return self.api_get(path)
        if path in {"/healthz"}:
            return self.send_json({"ok": True, "app": "CABEPEDES", "version": APP_VERSION})
        return self.static_file(path.lstrip("/"))

    def do_HEAD(self):
        if not valid_request_host(self):
            return self.send_json({"error": "Invalid Host header"}, 421)
        if not enforce_lan_tls(self):
            return
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        if path == "/" or path == "/index.html":
            return self.static_head("index.html")
        if path == "/log/security-audit.log":
            token, sess = parse_session(self)
            if not sess:
                return self.send_json({"error": "Authentication required"}, 401)
            if sess.get("role") != "Security Engineer":
                return self.send_json({"error": "Forbidden"}, 403)
            try:
                target = _audit_target()
                size = target.stat().st_size
                self.send_response(200); self.headers_common("text/plain; charset=utf-8", no_store=True); self.send_header("Content-Disposition", 'inline; filename="security-audit.log"'); self.send_header("Content-Length", str(size)); self.end_headers(); return
            except OSError:
                return self.send_json({"error": "Log audit tidak dapat dibaca saat ini."}, 503)
        if path in {"/healthz"}:
            body = json_bytes({"ok": True, "app": "CABEPEDES", "version": APP_VERSION})
            self.send_response(200); self.headers_common(no_store=True); self.send_header("Content-Length", str(len(body))); self.end_headers(); return
        return self.send_json({"error":"Not found"},404)

    def do_POST(self):
        if not valid_request_host(self):
            return self.send_json({"error": "Invalid Host header"}, 421)
        if not enforce_lan_tls(self):
            return
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        if path.startswith("/api/"):
            if not request_allowed(self.client_address[0]):
                return self.send_json({"error": "Too many requests"}, 429)
            return self.api_post(path)
        return self.send_json({"error": "Not found"}, 404)

    def do_PUT(self):
        if not valid_request_host(self):
            return self.send_json({"error": "Invalid Host header"}, 421)
        if not enforce_lan_tls(self):
            return
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        if path.startswith("/api/"):
            if not request_allowed(self.client_address[0]):
                return self.send_json({"error": "Too many requests"}, 429)
            return self.api_post(path)
        return self.send_json({"error": "Not found"}, 404)

    def do_DELETE(self):
        if not valid_request_host(self):
            return self.send_json({"error": "Invalid Host header"}, 421)
        if not enforce_lan_tls(self):
            return
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        if path.startswith("/api/"):
            if not request_allowed(self.client_address[0]):
                return self.send_json({"error": "Too many requests"}, 429)
            return self.api_delete(path)
        return self.send_json({"error": "Not found"}, 404)

    def static_file(self, rel):
        if rel in SENSITIVE_NAMES or rel.startswith(".") or "/" in rel or "\\" in rel or rel == "":
            audit("static_denied", ip=self.client_address[0], result="deny", detail=rel[:120])
            return self.send_json({"error": "Not found"}, 404)
        if rel not in STATIC_ALLOWLIST:
            return self.send_json({"error": "Not found"}, 404)
        path = BASE_DIR / rel
        if not path.exists() or not path.is_file():
            return self.send_json({"error": "Not found"}, 404)
        data = path.read_bytes()
        self.send_response(200)
        self.headers_common(STATIC_ALLOWLIST[rel], no_store=True)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def static_head(self, rel):
        if rel in SENSITIVE_NAMES or rel.startswith(".") or "/" in rel or "\\" in rel or rel == "" or rel not in STATIC_ALLOWLIST:
            return self.send_json({"error": "Not found"}, 404)
        path = BASE_DIR / rel
        if not path.exists() or not path.is_file():
            return self.send_json({"error": "Not found"}, 404)
        self.send_response(200); self.headers_common(STATIC_ALLOWLIST[rel], no_store=True); self.send_header("Content-Length", str(path.stat().st_size)); self.end_headers()

    def audit_authenticated_activity(self, token, sess, *, event, detail="", client=None, result="success"):
        info = client or client_identity(self, token)
        audit(event, ip=self.client_address[0], username=sess.get("username", ""), role=sess.get("role", ""), result=result, detail=detail, client=info, session=info.get("session", ""))

    def api_get(self, path):
        token, sess = parse_session(self)
        if path == "/api/session":
            if not sess:
                return self.send_json({"authenticated": False})
            info = client_identity(self, token)
            audit_client_if_changed(token, info, "session refresh")
            self.audit_authenticated_activity(token, sess, event="session_check", detail="GET /api/session", client=info)
            return self.send_json({
                "authenticated": True,
                "role": sess["role"],
                "username": sess["username"],
                "csrf": sess["csrf"],
                "expires_at": sess["expires_at"],
                "network": infer_network(self.secure),
            })
        if not sess:
            audit("access_denied", ip=self.client_address[0], result="deny", detail=f"unauthenticated GET {path}")
            return self.send_json({"error": "Authentication required"}, 401)
        if path == "/api/register":
            with DATA_LOCK:
                records = load_records()
            self.audit_authenticated_activity(token, sess, event="register_view", detail=f"GET /api/register;count={len(records)}")
            return self.send_json({"records": records, "count": len(records)})
        if path == "/api/audit/log":
            if sess["role"] != "Security Engineer":
                audit("access_denied", ip=self.client_address[0], username=sess["username"], role=sess["role"], result="deny", detail="audit log requires Security Engineer")
                return self.send_json({"error": "Forbidden"}, 403)
            try:
                target, rows = _audit_rows()
                stat = target.stat()
                info = client_identity(self, token)
                self.audit_authenticated_activity(token, sess, event="audit_log_view", detail=f"GET /api/audit/log;rows={len(rows)}", client=info)
                return self.send_json({
                    "ok": True,
                    "path": str(target),
                    "filename": target.name,
                    "size": stat.st_size,
                    "updated_at": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).astimezone().isoformat(timespec="seconds"),
                    "columns": AUDIT_COLUMNS,
                    "rows": rows,
                })
            except (OSError, ValueError):
                audit("audit_log_read_failed", ip=self.client_address[0], username=sess["username"], role=sess["role"], result="deny", detail="audit log read failed")
                return self.send_json({"error": "Log audit tidak dapat dibaca saat ini."}, 503)
        if path == "/api/clients":
            if sess["role"] != "Security Engineer":
                audit("access_denied", ip=self.client_address[0], username=sess["username"], role=sess["role"], result="deny", detail="active clients requires Security Engineer")
                return self.send_json({"error": "Forbidden"}, 403)
            info = client_identity(self, token)
            audit_client_if_changed(token, info, "active clients refresh")
            with LOCK:
                now = now_ts()
                active = [dict(v) for v in CLIENTS.values() if v.get("last_active", 0) + 120 >= now]
            now_audit = now_ts()
            last_view = ACTIVE_VIEW_AUDIT_TS.get(token, 0)
            if now_audit - last_view >= 60:
                ACTIVE_VIEW_AUDIT_TS[token] = now_audit
                audit("active_clients_view", ip=self.client_address[0], username=sess["username"], role=sess["role"], result="success", detail=f"count={len(active)}", client=info)
                for item in active:
                    audit_client_snapshot("active_client_snapshot", item, detail="visible in Active Clients panel")
            return self.send_json({"clients": active})
        if path == "/api/notifications":
            payload = notifications_for_user(sess["role"], sess["username"])
            self.audit_authenticated_activity(token, sess, event="notifications_view", detail=f"GET /api/notifications;count={payload.get('count', 0)};unread={payload.get('unread_count', 0)}")
            return self.send_json(payload)
        if path == "/api/release-notes":
            if sess["role"] != "Security Engineer":
                audit("access_denied", ip=self.client_address[0], username=sess["username"], role=sess["role"], result="deny", detail="release notes requires Security Engineer")
                return self.send_json({"error": "Forbidden"}, 403)
            self.audit_authenticated_activity(token, sess, event="release_notes_view", detail="GET /api/release-notes")
            return self.send_json({"ok": True})
        audit("api_not_found", ip=self.client_address[0], username=sess.get("username", ""), role=sess.get("role", ""), result="deny", detail=f"GET {path}")
        return self.send_json({"error": "Not found"}, 404)

    def api_post(self, path):
        ip = self.client_address[0]
        try:
            data = self.parse_json_body()
        except Exception as exc:
            audit("request_rejected", ip=ip, result="deny", detail=f"POST {path};invalid_json")
            return self.send_json({"error": "Invalid request"}, 400)

        if path == "/api/login":
            return self.login(data)

        token, sess = parse_session(self)
        if not sess:
            audit("access_denied", ip=ip, result="deny", detail=f"unauthenticated POST {path}")
            return self.send_json({"error": "Authentication required"}, 401)
        if not require_csrf(self, sess):
            return self.send_json({"error": "Forbidden"}, 403)

        if path == "/api/heartbeat":
            info = client_identity(self, token, data.get("client"), data.get("geo"))
            audit_client_if_changed(token, info, "heartbeat / device metadata or location change")
            return self.send_json({"ok": True, "server_time": now_iso()})

        if path == "/api/audit/event":
            if not rate_audit_event(token):
                audit("ui_audit_rate_limited", ip=ip, username=sess["username"], role=sess["role"], result="deny", detail="/api/audit/event rate limit")
                return self.send_json({"ok": False}, 429)
            event = clean_text(data.get("event", "ui_event"), 60)
            # Prevent arbitrary log injection/event names while retaining all supported UI actions.
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,60}", event):
                audit("ui_audit_rejected", ip=ip, username=sess["username"], role=sess["role"], result="deny", detail="invalid event name")
                return self.send_json({"error": "Invalid audit event"}, 400)
            detail = redact_sensitive_detail(clean_text(data.get("detail", ""), 500))
            info = client_identity(self, token, data.get("client"), data.get("geo"))
            audit(event, ip=ip, username=sess["username"], role=sess["role"], result="success", detail=detail, client=info, session=info.get("session",""))
            return self.send_json({"ok": True})

        if path == "/api/logout":
            with LOCK:
                info = dict(CLIENTS.get(token, {}))
                SESSIONS.pop(token, None)
                CLIENTS.pop(token, None)
                AUDIT_EVENT_BUCKETS.pop(token, None)
                ACTIVE_VIEW_AUDIT_TS.pop(token, None)
            audit("logout", ip=ip, role=sess["role"], result="success", username=sess["username"], client=info)
            return self.send_json({"ok": True}, 200, {"Set-Cookie": "cabepedes_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0", "X-CABEPEDES-Session-Cleared": "1"})

        if path == "/api/notifications/read":
            try:
                ids = data.get("ids", [])
                mark_all = bool(data.get("all"))
                if not isinstance(ids, list):
                    raise ValueError("ids must be list")
                ids = [clean_text(v, 80) for v in ids if isinstance(v, (str, int))][:100]
                result = mark_notifications_read(sess["role"], sess["username"], ids, mark_all=mark_all)
                self.audit_authenticated_activity(token, sess, event="notification_read", detail=f"POST /api/notifications/read;all={mark_all};count={len(ids)}")
                return self.send_json(result)
            except Exception:
                audit("request_rejected", ip=ip, username=sess["username"], role=sess["role"], result="deny", detail="POST /api/notifications/read;invalid_request")
                return self.send_json({"error": "Invalid notification request"}, 400)

        if sess["role"] != "Security Engineer":
            audit("role_denied", ip=ip, role=sess["role"], result="deny", username=sess["username"], detail=path)
            return self.send_json({"error": "Forbidden"}, 403)

        if path == "/api/register/create":
            try:
                payload = data.get("record")
                if not isinstance(payload, dict):
                    raise ValueError("record object required")
                record = validate_business_record(payload, allow_blank_id=True)
            except Exception as exc:
                return self.send_json({"error": str(exc) if str(exc) == "ID Issue is server-managed" else "Invalid record data"}, 400)
            with DATA_LOCK:
                records = load_records()
                new_id = next_issue_id(records)
                record["ID Issue"] = new_id
                if any(r["ID Issue"] == new_id for r in records):
                    return self.send_json({"error": "ID Issue collision; retry"}, 409)
                records.append(record)
                records = validate_records(records)
                atomic_write_json(DATA_FILE, records)
            try:
                create_notification(kind="va_created", roles=["Security Engineer", "Visitor"], actor_username=sess["username"], actor_role=sess["role"], record=record)
            except Exception as exc:
                audit("notification_create_failed", ip=ip, role=sess["role"], username=sess["username"], result="deny", detail=type(exc).__name__)
            audit("register_create", ip=ip, role=sess["role"], result="success", username=sess["username"], detail=f"id={new_id};application={record['Aplikasi / Sistem'][:120]}")
            return self.send_json({"record": record, "records": records, "count": len(records)})

        if path == "/api/register/update":
            try:
                record_id = clean_text(data.get("id", ""), 120)
                payload = data.get("record")
                if not record_id or not isinstance(payload, dict):
                    raise ValueError("invalid request")
                supplied_id = clean_text(payload.get("ID Issue", ""), 120)
                if supplied_id and supplied_id != record_id:
                    return self.send_json({"error": "ID Issue tidak dapat diubah."}, 400)
                payload = dict(payload)
                payload["ID Issue"] = record_id
                updated = validate_business_record(payload, allow_blank_id=False)
            except Exception as exc:
                if str(exc) == "ID Issue tidak dapat diubah.":
                    return self.send_json({"error": str(exc)}, 400)
                return self.send_json({"error": "Invalid record data"}, 400)
            with DATA_LOCK:
                records = load_records()
                before = next((dict(r) for r in records if r["ID Issue"] == record_id), None)
                if before is None:
                    return self.send_json({"error": "Record not found"}, 404)
                records = [updated if r["ID Issue"] == record_id else r for r in records]
                records = validate_records(records)
                atomic_write_json(DATA_FILE, records)
            changed_fields = [h for h in before if before.get(h, "") != updated.get(h, "") and h != "ID Issue"]
            if changed_fields:
                try:
                    create_notification(kind="va_updated", roles=["Security Engineer"], actor_username=sess["username"], actor_role=sess["role"], record=updated, changed_fields=changed_fields)
                except Exception as exc:
                    audit("notification_update_failed", ip=ip, role=sess["role"], username=sess["username"], result="deny", detail=type(exc).__name__)
                audit("register_update", ip=ip, role=sess["role"], result="success", username=sess["username"], detail=f"id={record_id};fields={','.join(changed_fields[:20])}")
            else:
                audit("register_save", ip=ip, role=sess["role"], result="success", username=sess["username"], detail=f"id={record_id};no_changes")
            return self.send_json({"record": updated, "records": records, "count": len(records), "changed_fields": changed_fields})

        if path == "/api/register/reset":
            with DATA_LOCK:
                before = load_records()
                records = validate_records(load_json(BASELINE_FILE))
                atomic_write_json(DATA_FILE, records)
            audit("register_reset", ip=ip, role=sess["role"], result="success", username=sess["username"], detail=f"before={len(before)} after={len(records)}")
            return self.send_json({"records": records, "count": len(records)})

        audit("api_not_found", ip=ip, username=sess.get("username", ""), role=sess.get("role", ""), result="deny", detail=f"POST {path}")
        return self.send_json({"error": "Not found"}, 404)

    def api_delete(self, path):
        token, sess = parse_session(self)
        if not sess:
            audit("access_denied", ip=self.client_address[0], result="deny", detail=f"unauthenticated DELETE {path}")
            return self.send_json({"error": "Authentication required"}, 401)
        if sess["role"] != "Security Engineer" or not require_csrf(self, sess):
            return self.send_json({"error": "Forbidden"}, 403)
        if path != "/api/register/delete":
            audit("api_not_found", ip=self.client_address[0], username=sess["username"], role=sess["role"], result="deny", detail=f"DELETE {path}")
            return self.send_json({"error": "Not found"}, 404)
        try:
            data = self.parse_json_body()
            record_id = clean_text(data.get("id", ""), 120)
        except Exception:
            return self.send_json({"error": "Invalid request"}, 400)
        with DATA_LOCK:
            records = load_records()
            new_records = [r for r in records if r['ID Issue'] != record_id]
            if len(new_records) == len(records):
                return self.send_json({"error": "Record not found"}, 404)
            atomic_write_json(DATA_FILE, new_records)
        audit("register_delete", ip=self.client_address[0], role=sess["role"], result="success", username=sess["username"], detail=record_id)
        return self.send_json({"records": new_records, "count": len(new_records)})

    def login(self, data):
        ip = self.client_address[0]
        role = clean_text(data.get("role", ""), 40)
        username = clean_text(data.get("username", ""), 120).strip()
        password = clean_text(data.get("password", ""), 200)
        client = data.get("client") if isinstance(data.get("client"), dict) else {}
        login_client = {
            "ip": ip,
            "device_name": clean_text(client.get("device_name", ""), 120) if isinstance(client, dict) else "",
            "device_type": clean_text(client.get("device_type", ""), 60) if isinstance(client, dict) else "",
            "os": clean_text(client.get("os", ""), 120) if isinstance(client, dict) else "",
            "browser": clean_text(client.get("browser", ""), 120) if isinstance(client, dict) else "",
            "location_status": "unknown",
        }
        audit("login_attempt", ip=ip, role=role, username=username, result="received", detail="authentication attempt", client=login_client)
        if not rate_allowed(ip):
            record_failed_auth(ip)
            return self.send_json({"error": "Terlalu banyak percobaan. Silakan tunggu beberapa menit."}, 429)
        if role not in {"Security Engineer", "Visitor"} or not validate_username(role, username):
            record_failed_auth(ip)
            audit("login_failed", ip=ip, role=role, result="deny", username=username, detail="invalid role or username", client=login_client)
            return self.send_json({"error": "Username, role, atau password tidak valid."}, 401)
        engineers = parse_credentials(SECENG_FILE, visitor=False)
        visitors = parse_credentials(VISITOR_FILE, visitor=True)
        ok = False
        canonical_username = username
        if role == "Security Engineer":
            pair = engineers.get(username.casefold())
            ok = bool(pair and verify_password(password, pair[1]))
            if pair:
                canonical_username = pair[0]
        else:
            canonical = visitors.get(username.casefold())
            ok = bool(canonical)
            if canonical:
                canonical_username = canonical
        if not ok:
            record_failed_auth(ip)
            audit("login_failed", ip=ip, role=role, result="deny", detail="credential mismatch", username=username, client=login_client)
            return self.send_json({"error": "Username, role, atau password tidak valid."}, 401)

        clear_failed_auth(ip)
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        ts = now_ts()
        expires = ts + SESSION_IDLE[role]
        sess = {"username": canonical_username, "role": role, "csrf": csrf, "created_at": ts, "last_active": ts, "expires_at": expires}
        with LOCK:
            SESSIONS[token] = sess
        info = client_identity(self, token, client)
        audit("login_success", ip=ip, role=role, result="success", username=canonical_username, client=info)
        audit_client_if_changed(token, info, "login / initial device registration")
        secure = self.secure
        cookie = secure_cookie_header(token, secure, int(SESSION_IDLE[role]))
        return self.send_json({
            "authenticated": True,
            "role": role,
            "username": canonical_username,
            "csrf": csrf,
            "expires_at": expires,
            "network": infer_network(secure),
        }, 200, {"Set-Cookie": cookie})


class LocalHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class SecureHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve_forever(server):
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()


def port_in_use(port: int, bind_host: str = "0.0.0.0") -> bool:
    """Check whether the requested IPv4 listener can be bound, including LAN-only conflicts."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((bind_host, port))
            return False
        except OSError:
            return True


def cabepedes_instance_alive() -> bool:
    try:
        req = Request(f"{LOCAL_OPEN_URL}healthz", headers={"Accept": "application/json"})
        with urlopen(req, timeout=1) as response:
            payload = json.loads(response.read().decode("utf-8"))
            return response.status == 200 and payload.get("app") == "CABEPEDES"
    except Exception:
        return False


def open_local_browser() -> None:
    if sys.platform == "darwin" and os.environ.get("CABEPEDES_NO_OPEN") != "1":
        try:
            subprocess.Popen(["open", LOCAL_OPEN_URL], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass


def integrity_status():
    try:
        manifest = load_json(INTEGRITY_MANIFEST)
        entries = manifest.get("files", {})
        mismatches = []
        for rel in INTEGRITY_FILES:
            expected = entries.get(rel)
            path = BASE_DIR / rel
            if not expected or not path.exists() or sha256_bytes(path.read_bytes()) != expected:
                mismatches.append(rel)
        return (not mismatches), mismatches
    except Exception as exc:
        return False, [type(exc).__name__]


def verify_integrity() -> bool:
    try:
        ok, mismatches = integrity_status()
        if not ok:
            detail = ",".join(mismatches)[:450]
            audit("integrity_mismatch", result="deny", detail=detail)
            print("CABEPEDES integrity check failed:", ", ".join(mismatches), file=sys.stderr)
            return False
        audit("integrity_check", result="success", detail=f"files={len(INTEGRITY_FILES)}")
        return True
    except Exception as exc:
        audit("integrity_check_error", result="deny", detail=type(exc).__name__)
        print("CABEPEDES integrity check unavailable:", type(exc).__name__, file=sys.stderr)
        return False


def main():
    if not verify_integrity():
        return 2
    lock_handle = instance_lock()
    if lock_handle is None:
        if cabepedes_instance_alive():
            while cabepedes_instance_alive():
                time.sleep(30)
            return 0
        return 4
    try:
        os.chmod(DATA_FILE, 0o600)
        os.chmod(BASELINE_FILE, 0o600)
        os.chmod(SECENG_FILE, 0o600)
        os.chmod(VISITOR_FILE, 0o600)
    except OSError:
        pass
    ensure_audit_log()
    audit("runtime_audit_ready", result="success", detail=f"path={AUDIT_LOG.relative_to(BASE_DIR) if AUDIT_LOG.is_relative_to(BASE_DIR) else AUDIT_LOG}")
    if not DATA_FILE.exists():
        atomic_write_json(DATA_FILE, load_json(BASELINE_FILE))

    if port_in_use(LOCAL_PORT, HTTP_BIND_HOST):
        if cabepedes_instance_alive():
            audit("server_already_running", result="success", detail=f"http={LOCAL_PORT}")
            open_local_browser()
            return 0
        print(f"CABEPEDES cannot start: HTTP port {LOCAL_PORT} is already in use.", file=sys.stderr)
        audit("http_port_unavailable", result="deny", detail=f"port={LOCAL_PORT};bind={HTTP_BIND_HOST}")
        return 3

    tls_ok = ensure_tls()
    run_security_self_check()
    try:
        httpd = LocalHTTPServer((HTTP_BIND_HOST, LOCAL_PORT), Handler)
    except OSError as exc:
        audit("http_start_failed", result="deny", detail=type(exc).__name__)
        print(f"CABEPEDES cannot bind HTTP {HTTP_BIND_HOST}:{LOCAL_PORT}: {type(exc).__name__}", file=sys.stderr)
        return 3
    threads = [threading.Thread(target=serve_forever, args=(httpd,), daemon=True, name="cabepedes-http")]
    threads[0].start()
    httpsd = None
    if tls_ok:
        if port_in_use(TLS_PORT):
            audit("https_port_unavailable", result="deny", detail=f"port={TLS_PORT}")
            tls_ok = False
        else:
            try:
                httpsd = SecureHTTPServer((TLS_BIND_HOST, TLS_PORT), Handler)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.load_cert_chain(str(CERT_FILE), str(KEY_FILE))
                httpsd.socket = ctx.wrap_socket(httpsd.socket, server_side=True)
                threads.append(threading.Thread(target=serve_forever, args=(httpsd,), daemon=True, name="cabepedes-https"))
                threads[-1].start()
            except (OSError, ssl.SSLError) as exc:
                audit("https_start_failed", result="deny", detail=type(exc).__name__)
                if httpsd:
                    try:
                        httpsd.server_close()
                    except Exception:
                        pass
                httpsd = None
                tls_ok = False
    lan_ips = available_lan_ips()
    audit("server_start", result="success", detail=f"http={LOCAL_PORT};https={TLS_PORT if tls_ok else 0};lan_ips={','.join(lan_ips[:12])}")
    print(f"CABEPEDES LAN URL(s): {', '.join(f'https://{ip}:{TLS_PORT}/' for ip in lan_ips) or 'none'}", flush=True)
    monitor = threading.Thread(target=security_monitor, daemon=True, name="cabepedes-security-monitor")
    monitor.start()
    open_local_browser()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        audit("server_stop", result="success")
        httpd.shutdown()
        if httpsd:
            httpsd.shutdown()
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
            lock_handle.close()
        except Exception:
            pass

if __name__ == "__main__":
    raise SystemExit(main())
