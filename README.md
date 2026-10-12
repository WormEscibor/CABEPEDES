# CABEPEDES v1.3.2
## Central Audit & Bug Exploitation: Pentest Event Dashboard for Executive Summary

Runtime: Python standard library, no Node.js/npm/database/CDN.

## Akses
- Lokal: `http://localhost:1500/`
- LAN: `https://<IP-Mac>:1501/`
- LAN HTTP helper: `http://<IP-Mac>:1500/` otomatis diarahkan ke HTTPS LAN `:1501`.
- Untuk perangkat lain, gunakan **IP Mac server**, bukan `localhost`/`127.0.0.1`.
- Mac: double-click `CABEPEDES.app` atau `install.command` sekali.
- Instalasi pertama membuat salinan permanen di `~/Applications/CABEPEDES` dan memasang LaunchAgent user dengan `RunAtLoad + KeepAlive`; setelah itu CABEPEDES berjalan mandiri saat login/restart tanpa terminal. Reinstall/upgrade dari paket yang lebih baru memperbarui code tanpa menimpa data, credential, audit log, atau TLS state pengguna. Bila `seceng.txt` atau `visitor.txt` pada paket sumber diedit lalu lebih baru daripada file instalasi, installer akan mensinkronkannya ke `~/Applications/CABEPEDES/`; perubahan langsung pada file instalasi tetap dipertahankan bila lebih baru.
- `start.command` dan `run.sh` bersifat idempoten: keduanya hanya memastikan service aktif dan membuka browser. Mode foreground hanya tersedia untuk QA dengan `CABEPEDES_FOREGROUND=1 sh run.sh`.

## Credential Security Engineer
`seceng.txt` tidak lagi menyimpan plaintext password. Password disimpan sebagai PBKDF2-HMAC-SHA256 dengan salt acak unik per akun dan 600.000 iterasi. CABEPEDES membaca `seceng.txt` ulang setiap kali login, sehingga penambahan username/password baru berlaku tanpa restart. Format `Username:`/`Password:` toleran terhadap spasi di sekitar `:`, baris kosong, komentar, CRLF dan UTF-8 BOM. CABEPEDES menerima password saat login untuk verifikasi terhadap hash; password plaintext tidak dapat dipulihkan dari file.

## Log Audit Keamanan
Log aplikasi disimpan pada `log/security-audit.log` sebagai log runtime dalam format tabel dengan 13 kolom. Apabila folder aplikasi tidak dapat ditulis, server menggunakan `~/Library/Logs/CABEPEDES/security-audit.log` sebagai lokasi cadangan. Security Engineer dapat melihat kegiatan audit melalui panel Log Keamanan pada aplikasi atau membuka `http://localhost:1500/log/security-audit.log` setelah login. Nama pengguna asli dicatat untuk kebutuhan audit, sedangkan kata sandi, hash kata sandi, token, cookie, dan rahasia tidak dicatat. Kegiatan yang dicatat mencakup login, logout, pemeriksaan hak akses, menu, filter, tambah, ubah, hapus, reset Data Register, Active Clients, informasi perangkat, lokasi, notifikasi, dan aktivitas sesi.

## Active Clients
Lokasi berasal dari Browser Geolocation API dengan `enableHighAccuracy`. Akurasi nyata bergantung pada izin, sensor, OS, browser dan jaringan. Nama perangkat bersifat best-effort karena browser tidak memberikan hostname komputer secara umum.

## Security Monitor
Kontrol background dan defensive hardening dipetakan ke **OWASP Top 10:2025**, **OWASP ASVS 5.0.0**, **ISO/IEC 27001:2022**, **NIST SP 800-53 Rev. 5 / minor release 5.2.0**, **NIST Cybersecurity Framework 2.0**, **CWE / SANS-oriented secure coding**, dan **PTES v1.0**. Self-check mencakup access control, security headers/TLS, credential hashing, integrity manifest, file permissions, session hygiene, CSRF, input/body limits, schema validation, audit logging, atomic persistence, notification recovery, dan deny-by-default static/API routing.

Pemetaan ini adalah **implementasi kontrol teknis dan engineering baseline**, bukan sertifikasi ISO/IEC 27001, attestation ASVS, atau pengganti independent penetration test. Visitor tetap menggunakan model identitas allowlist sesuai workflow aplikasi; untuk assurance tingkat tinggi, deployment organisasi dapat menambahkan autentikasi Visitor yang lebih kuat/MFA sebelum menyatakan pemenuhan kontrol autentikasi tertentu secara formal.

## Data & Formula Parity
- 61 record × 16 kolom A–P.
- Baseline: Total 61, Open 39, Closed 22, High 15.
- Severity: High 15, Medium 22, Low 12.
- 31 formula source workbook.

## Catatan Rilis
Lihat `RELEASE_NOTES.md` untuk riwayat lengkap. Rilis v1.3.2 menambahkan penyaringan Data Register berdasarkan bulan dan pemilihan kolom dengan checkbox. Rilis ini juga mempertahankan perbaikan jaringan, pemuatan akun secara dinamis, dan tampilan log audit dari v1.3.1.
