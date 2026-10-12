# CABEPEDES v1.3.2 — Final QA & Security Verification Report

**Tanggal QA:** 24 September 2026  
**Aplikasi:** CABEPEDES | Central Audit & Bug Exploitation: Pentest Event Dashboard for Executive Summary

## v1.3.2 Verification — 25 September 2026

- Data Register menambahkan penyaringan berdasarkan bulan dan tahun dari `Tanggal Temuan`.
- Data Register menambahkan pilihan 16 kolom menggunakan checkbox tanpa mengubah data sumber.
- Sedikitnya satu kolom dijaga tetap aktif agar tabel tidak menjadi kosong.
- Kolom `ID Issue` hanya menggunakan perilaku sticky ketika dipilih.
- Pemeriksaan sintaks Python, JavaScript, shell, JSON, dan XML/Property List dilakukan kembali setelah perubahan.

## 1. Scope

Audit mencakup seluruh source utama yang relevan terhadap startup, HTTP/API, authentication/RBAC, CSRF/session, integrity gate, persistence, annual Issue ID, notifications, frontend performance, release packaging dan static/integration security tests.

## 2. Data Baseline

- Baseline aplikasi: **61 record × 16 kolom**.
- Baseline KPI: **Total 61, Open 39, Closed 22, High 15**.
- Severity baseline: **High 15, Medium 22, Low 12**.
- `SOURCE_WORKBOOK.xlsx` tetap sebagai artefak referensi dan **bukan dependency startup integrity gate**.

## 3. Persistent macOS Startup

- Instalasi pertama menyalin runtime ke `~/Applications/CABEPEDES`.
- User LaunchAgent berada di `~/Library/LaunchAgents/id.kemkes.csirt.cabepedes.plist`.
- `RunAtLoad=true`, `KeepAlive` aktif, `ThrottleInterval=5`, dan launcher menggunakan kandidat path Python yang stabil.
- Service dikelola `launchd`, bukan child process Terminal.
- Reinstall/upgrade mempertahankan data, credential, audit log dan TLS state pengguna.
- `run.sh`, `start.command`, dan `install.command` idempoten.
- **Static verification: PASS.** Eksekusi native `launchctl`/Finder/browser setelah reboot tidak tersedia di Linux build environment dan harus diverifikasi pada Mac target.

## 4. Integrity & Supply-Chain Hygiene

- SHA-256 integrity gate mencakup **17 immutable executable/static release assets**.
- Mutable runtime (`data-register.json`, `notifications.json`, credentials, logs, `.tls`, workbook) tidak diperlakukan sebagai immutable release code.
- Tampering terhadap `app.js` membuat integrity self-check gagal dan process exit menjadi **2**.
- `SOURCE_WORKBOOK.xlsx` berubah secara sah tanpa mematikan startup.
- Release ZIP tidak menyertakan private TLS key, data sesi, atau artefak QA. Paket menyertakan `log/security-audit.log` dengan schema resmi 13 kolom dan satu event `audit_log_initialized` berjenis SYSTEM sebagai penanda inisialisasi release; seluruh event user nyata ditambahkan oleh `server.py` saat runtime. Paket juga tidak menyertakan `.DS_Store`, `__MACOSX`, `.pyc` atau `__pycache__`.

## 5. Authentication, RBAC, Session & CSRF

- Security Engineer password menggunakan PBKDF2-HMAC-SHA256 **600.000 iterasi** dengan salt unik.
- Constant-time comparison digunakan untuk secret/token verification.
- Session mempunyai idle timeout; logout dicabut server-side.
- Cookie menggunakan `HttpOnly`, `SameSite=Strict`, dan `Secure` pada HTTPS.
- CSRF diwajibkan pada endpoint state-changing.
- Visitor tetap read-only dan tidak dapat melakukan CRUD/Active Clients.
- Visitor identity masih berupa allowlist sesuai workflow lama; ini merupakan residual assurance consideration dan tidak diklaim sebagai pemenuhan formal semua requirement autentikasi ASVS.

## 6. Server-Authoritative Issue ID

- Create **tidak menerima ID Issue buatan client**; server selalu mengalokasikan ID berikutnya.
- Update menjadikan ID pada URL/path sebagai sumber kebenaran dan menolak mismatch ID di body.
- Format: `VA-YYYY-NNN`.
- Saat tahun berganti, counter otomatis dimulai dari `001`; contoh berikutnya pada 2027 adalah `VA-2027-001`.
- ID UI dibuat readonly/disabled agar Security Engineer tidak salah input.
- Regression: create dengan ID palsu **REJECTED 400**; update tamper ID **REJECTED 400**; rollover **PASS**.

## 7. Notifications

- VA baru yang dibuat Security Engineer menghasilkan notifikasi ke semua Security Engineer dan Visitor berisi ID Issue, Aplikasi/Sistem, PIC, dan actor.
- Perubahan VA menghasilkan notifikasi ke semua Security Engineer berisi actor dan daftar field yang berubah.
- Notification store memakai atomic write, permission `0600`, batas retention 500 item dan fallback `.bak` terverifikasi.
- Read state bersifat per-user; Visitor hanya dapat menandai notification miliknya sendiri.
- Regression create/update/read notification: **PASS**.

### 7A. Audit Log Release Artifact

- Folder `log/` disertakan di paket rilis.
- File `log/security-audit.log` berisi header tabel audit yang konsisten dengan runtime: `Timestamp | Event | Role | Username | IP | Device | Type | Location | OS | Browser | Session | Result | Detail`.
- Release artifact tidak memuat data aktivitas pengguna/QA. `server.py` menambahkan event nyata melalui `audit()` setiap kali aktivitas yang diaudit terjadi.
- Runtime menegakkan permission folder `0700` dan file `0600`, serta melakukan rotasi pada 4 MiB.
- Log dapat dibaca melalui panel **Log Keamanan** oleh Security Engineer dan dapat dibuka sebagai teks melalui `/log/security-audit.log` setelah autentikasi. Visitor tetap menerima `403`.
- Jika lokasi utama tidak dapat digunakan, panel dan pemeriksaan keamanan membaca lokasi log cadangan yang sama dengan lokasi yang digunakan server.

### 7B. Runtime Audit Verification

- Runtime integration test berhasil menulis 36 event ke `log/security-audit.log` dari sesi Security Engineer dan Visitor, termasuk `login_attempt`, `login_failed`, `login_success`, `client_presence`, `session_check`, `register_view`, `notifications_view`, `active_clients_view`, `release_notes_view`, `menu_click`, `search_used`, `record_edit_open`, `notification_panel_open`, `register_create`, `register_update`, `notification_read`, `role_denied`, dan `access_denied`.
- Setiap baris runtime tervalidasi memiliki tepat **13 kolom**.
- Context sesi Security Engineer terbukti memuat username, IP, device, type, OS, browser, dan session identifier.
- Password plaintext, password hash, dan test secret **tidak ditemukan** di audit log.
- Audit write memakai lock serialisasi, flush, fallback user-scoped dan diagnostic error reporting; permission tetap `0600`.

## 8. API/HTTP Hardening

- Host validation dan local-vs-LAN binding diperketat.
- Local HTTP dibatasi ke loopback; non-loopback HTTP diarahkan ke HTTPS.
- TLS minimum 1.2.
- Security headers meliputi CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, COOP/CORP, Permissions-Policy, X-DNS-Prefetch-Control, X-Permitted-Cross-Domain-Policies dan HSTS pada TLS.
- Static serving menggunakan allowlist; source, credential, workbook, manifest, logs dan private TLS material tidak diekspos.
- Request body dibatasi 512 KiB; mutating API rate limited; JSON/schema validation aktif.
- Error response tidak membocorkan traceback/secret.

## 9. Persistence & Recovery

- JSON state ditulis atomic melalui temporary file + `fsync` + `os.replace`.
- Backup `.bak` digunakan sebagai recovery saat corruption.
- Data hasil recovery divalidasi schema sebelum dipakai.
- Credential/log/runtime files diberi permission terbatas.

## 10. Performance / M1 Server Footprint

- Browser polling diturunkan: heartbeat 30 detik, register refresh 45 detik, notifications 15 detik, active clients 20 detik.
- Backend memakai Python standard library tanpa Node.js/npm/database/CDN.
- Notification polling hanya mengambil metadata ringan; dashboard tetap menggunakan single-page asset set.
- Single-instance lock mencegah duplicate server process.

## 11. Static QA

- Python syntax: **PASS** (`py_compile`).
- JavaScript syntax: **PASS** (`node --check app.js`, `logic.js`).
- Shell syntax: **PASS** (`sh -n run.sh bootstrap.sh server-launcher.sh start.command install.command`).
- JSON parse: **PASS** untuk release JSON assets.
- Info.plist parse: **PASS**.
- Dangerous JS primitive scan (`eval`, `new Function`, `document.write`): **NONE FOUND**.
- Clean release integrity verification: **PASS (17/17)**.

## 12A. Release History UI Verification

- Dashboard Security Center menampilkan **23 September 2026 — v1.3.0**, **23 September 2026 — v1.2.0**, dan **20 Agustus 2026 — v1.1.0**.
- Daftar v1.2.0 tidak lagi kosong dan memuat seluruh kelompok hardening/reliability yang diwariskan.
- Riwayat v1.1.0 memuat baseline 20 Agustus 2026 dan pengembangan lanjutan 23 September 2026.
- `RELEASE_NOTES.md` dan UI menggunakan sejarah yang sama sehingga tidak terjadi divergence dokumentasi.

## 11A. v1.3.1 Audit Log & Documentation Verification — 24 September 2026

- Endpoint `/api/audit/log`: **200 PASS** untuk Security Engineer dan mengembalikan 13 kolom audit.
- URL `/log/security-audit.log`: **401 PASS** tanpa sesi dan **200 PASS** setelah login sebagai Security Engineer.
- Visitor mengakses `/api/audit/log`: **403 PASS**.
- Penambahan akun Security Engineer pada `seceng.txt` setelah server berjalan: **200 PASS** saat login tanpa restart.
- Penambahan akun Visitor pada `visitor.txt` setelah server berjalan: **200 PASS** saat login tanpa restart.
- Simulasi lokasi log utama yang tidak dapat digunakan: lokasi cadangan dipilih dan `audit_log_schema` serta `audit_log_permissions` tetap **PASS**.
- Tidak ditemukan error pada stderr selama pengujian runtime.
- JavaScript tidak lagi memanggil daftar riwayat v1.2.0 yang sudah dihapus dari HTML.
- `RELEASE_NOTES.md` dan Riwayat Fitur pada antarmuka menggunakan istilah Bahasa Indonesia yang lebih formal dan konsisten untuk empat rilis yang ditampilkan.

## 12. Integration Test Result

- `/healthz`: **200 PASS**.
- Security headers: **PASS**.
- Invalid Host: **421 PASS**.
- Visitor login: **200 PASS**.
- Baseline: **61 PASS**.
- Create tampered ID: **400 PASS**.
- Create server ID: **VA-2026-062 PASS**.
- Visitor creation notification: **PASS**.
- Visitor mark-read isolation: **PASS**.
- Engineer update changed-fields notification: **PASS**.
- Update tampered ID: **400 PASS**.
- Visitor create mutation: **403 PASS**.
- 2027 rollover: **VA-2027-001 PASS**.
- Corrupt state recovery from verified backup: **PASS**.
- Integrity tamper detection: **PASS**, identifies `app.js` and returns non-zero exit status.
- Server stderr during integration: **EMPTY / PASS**.

## 13. Standards Control Mapping

The release engineering baseline is mapped to:

- **OWASP Top 10:2025** — application risks and defensive controls.
- **OWASP ASVS 5.0.0** — verification-oriented application security control structure.
- **ISO/IEC 27001:2022** — information-security management/control context; this package is not an ISO certification.
- **NIST SP 800-53 Rev. 5 / 5.2.0** — security/privacy control references.
- **NIST CSF 2.0** — Govern, Identify, Protect, Detect, Respond, Recover oriented practices.
- **CWE / SANS-oriented secure coding** — weakness avoidance and defensive coding references.
- **PTES v1.0** — penetration-testing lifecycle/test-method context.

This is a technical control mapping and hardening report, not a third-party certification or independent penetration-test attestation.

## 14. Release Decision

The build is **release-ready from the source/static/integration QA executable in this environment**, with one explicit platform validation remaining: run the packaged app on the target Mac, reboot macOS, verify the LaunchAgent starts the server without Terminal, confirm `http://localhost:1500/`, and verify the HTTPS LAN listener if remote access is required.

## v1.3.1 Hotfix Verification — 24 September 2026

Source-level and local integration checks performed for this patch: Python syntax compilation, shell syntax validation, dynamic `visitor.txt` parser tests, dynamic `seceng.txt` PBKDF2 parser/verification tests, localhost HTTP health check, LAN HTTP redirect check, and LAN HTTPS health check. All checks passed in the available test environment.

The patch changes the HTTP listener from loopback-only to `0.0.0.0:1500`, permits validated LAN Host headers through the HTTP-to-HTTPS redirect path, keeps HTTPS on `0.0.0.0:1501`, and reloads credentials from disk on each login. Target macOS application startup, macOS Application Firewall behavior, and browser trust behavior for the self-signed LAN certificate still require validation on the deployment Mac because those platform-specific conditions are not reproducible in this environment.
