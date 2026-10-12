# CABEPEDES — Riwayat Fitur dan Catatan Rilis

Dokumen ini mencatat perubahan utama CABEPEDES berdasarkan tanggal rilis. Istilah teknis seperti PBKDF2-HMAC-SHA256, LaunchAgent, SHA-256, TLS, OWASP, dan Geolocation API dipertahankan karena merupakan nama teknologi atau standar.

## 25 September 2026 — v1.3.2 — Penyaringan Bulan dan Pilihan Kolom Data Register

Penyempurnaan pada Data Register untuk memudahkan pengguna menyaring data dan menyesuaikan tampilan tabel sesuai kebutuhan.

1. Data Register dapat disaring berdasarkan **Bulan Temuan** menggunakan kolom `Tanggal Temuan`.
2. Pilihan bulan menampilkan **bulan dan tahun** sehingga data pada tahun yang berbeda tidak tercampur.
3. Ditambahkan pemilih kolom berbasis **checkbox** untuk memilih data yang ditampilkan dari 16 kolom Data Register.
4. Disediakan tombol **Pilih semua** untuk mengembalikan seluruh kolom tanpa mengubah data sumber.
5. Sedikitnya satu kolom wajib tetap ditampilkan agar tabel tetap dapat dibaca dan digunakan.
6. Kolom `ID Issue` hanya dibuat tetap saat kolom tersebut dipilih, sehingga tata letak tabel tetap konsisten setelah kolom lain disembunyikan.
7. Kegiatan penyaringan bulan dan pemilihan kolom dicatat dalam log audit antarmuka.

## 24 September 2026 — v1.3.1 — Perbaikan Jaringan dan Kredensial

Perbaikan pada rilis ini ditujukan untuk memastikan CABEPEDES dapat digunakan dari perangkat lain pada jaringan yang sama dan untuk memudahkan pengelolaan akun tanpa mengubah kode sumber.

1. Server HTTP pada port 1500 menerima koneksi dari jaringan, bukan hanya dari komputer tempat server berjalan.
2. Akses HTTP dari perangkat lain pada jaringan yang sama dialihkan secara otomatis ke HTTPS port 1501. Akses `localhost` tetap tersedia melalui HTTP port 1500.
3. Pemeriksaan `Host` diperbaiki agar alamat IP LAN dapat melewati proses pengalihan ke HTTPS dengan benar.
4. `visitor.txt` dan `seceng.txt` dibaca kembali setiap kali login. Penambahan akun baru dapat langsung digunakan tanpa menjalankan ulang server.
5. Pembacaan berkas kredensial menerima spasi di sekitar tanda titik dua, baris kosong, komentar, UTF-8 BOM, dan format baris CRLF.
6. Pemasangan ulang memperbarui berkas kredensial dari paket sumber apabila berkas tersebut lebih baru. Perubahan yang lebih baru pada instalasi tetap dipertahankan.
7. Ditambahkan tampilan Log Keamanan untuk Security Engineer. Tampilan tersebut membaca log runtime yang benar-benar digunakan server, termasuk lokasi cadangan apabila lokasi utama tidak dapat ditulis.
8. Pemeriksaan keamanan sekarang memeriksa lokasi log runtime yang aktif sehingga penggunaan log cadangan tidak langsung dianggap sebagai kegagalan.
9. Bagian Riwayat Fitur CABEPEDES ditulis ulang menggunakan Bahasa Indonesia yang formal, jelas, dan mudah dipahami.

## 23 September 2026 — v1.3.0 — Catatan Rilis Terpadu

Rilis ini menyatukan catatan pengembangan yang sebelumnya tersebar pada 23 September 2026. Tujuannya agar perubahan aplikasi, pengamanan, pencatatan audit, dan penyempurnaan penggunaan dapat dibaca dalam satu riwayat yang utuh.

1. Proses startup aplikasi berjalan melalui LaunchAgent pengguna sehingga server dapat aktif kembali setelah pengguna masuk ke macOS atau setelah Mac dinyalakan ulang.
2. Log audit dibuat oleh server dengan 13 kolom: waktu, kegiatan, peran, nama pengguna, alamat IP, perangkat, jenis perangkat, lokasi, sistem operasi, peramban, sesi, hasil, dan keterangan.
3. Pencatatan audit mencakup autentikasi, sesi, dashboard, Data Register, notifikasi, Active Clients, pencarian, penyaringan, penambahan, perubahan, penghapusan, reset, penolakan hak akses, pemeriksaan keamanan, dan siklus hidup server.
4. Penulisan log dilakukan secara berurutan. Pemisah tabel dan baris baru disanitasi, hak akses berkas dibatasi, rotasi log diterapkan, dan tersedia lokasi cadangan.
5. Pencatatan kegiatan pada antarmuka menggunakan antrean berurutan dan percobaan ulang agar kegiatan tidak mudah hilang ketika beberapa permintaan terjadi bersamaan.
6. Log runtime digunakan sebagai sumber audit setelah pemasangan agar operator tidak keliru memeriksa berkas contoh pada paket rilis.
7. Nomor ID Issue dikelola oleh server menggunakan pola `VA-YYYY-NNN` dan kembali ke nomor `001` pada pergantian tahun.
8. Notifikasi dibuat untuk data temuan baru bagi Security Engineer dan Visitor, serta untuk perubahan data temuan bagi Security Engineer.
9. Waktu pada halaman login dan dashboard ditampilkan secara langsung hingga detik.
10. Pemutakhiran berkala dibatasi agar beban aplikasi tetap ringan.
11. Pemeriksaan integritas hanya mencakup berkas rilis yang tidak berubah selama penggunaan. Data, kredensial, log, dan keadaan TLS tetap dapat berubah sebagai data operasional.
12. Ikon peramban menggunakan `Logo Browser.png`, sedangkan identitas aplikasi menggunakan `Logo CabePedes.png`.
13. Grafik dashboard disusun dengan pembedaan warna berdasarkan tingkat keparahan dan kelompok data agar informasi lebih mudah dibaca.
14. Halaman login menggunakan tampilan terkunci, validasi masukan, pesan kesalahan pada kolom, serta perlindungan terhadap interaksi sebelum autentikasi selesai.
15. Visitor dapat masuk menggunakan nama lengkap beserta gelar tanpa kata sandi sesuai daftar yang tercatat.
16. Akun Security Engineer dan Visitor dibaca dari `seceng.txt` dan `visitor.txt` tanpa menggunakan basis data.
17. Pembatasan hak akses diterapkan di sisi server. Security Engineer memiliki hak pengelolaan, sedangkan Visitor hanya dapat membaca Dashboard dan Data Register.
18. Informasi peran dan nama pengguna sesi ditampilkan pada bagian atas aplikasi.
19. Akses jaringan menggunakan server Python bawaan, HTTPS untuk koneksi LAN, pembukaan peramban otomatis pada Mac, dan mekanisme startup yang dapat dijalankan berulang kali dengan aman.
20. Active Clients menampilkan alamat IP, nama perangkat, jenis perangkat, lokasi, sistem operasi, peramban, sesi, dan waktu terakhir aktif.
21. Informasi lokasi menggunakan Geolocation API dengan `enableHighAccuracy`. Ketepatan lokasi bergantung pada perangkat, sistem operasi, izin, jaringan, dan kondisi lingkungan.

### 23 September 2026 — Bagian Pengembangan yang Dihimpun dari v1.2.0

Catatan berikut merupakan perubahan yang menjadi dasar penguatan keamanan dan keandalan sebelum disatukan ke dalam rilis v1.3.0.

- Aplikasi lokal tersedia melalui `http://localhost:1500/`, sedangkan akses jaringan menggunakan HTTPS pada port 1501.
- Proses startup dipindahkan ke LaunchAgent pengguna dengan `RunAtLoad` dan `KeepAlive`.
- Lokasi pemasangan aplikasi dibuat dapat dipindahkan tanpa mengubah konfigurasi secara manual.
- Kata sandi Security Engineer disimpan menggunakan PBKDF2-HMAC-SHA256 dengan 600.000 iterasi dan salt yang berbeda untuk setiap akun.
- `security-audit.log` menyimpan kegiatan audit tanpa mencatat kata sandi.
- Pemeriksaan keamanan latar belakang memantau hak akses berkas, integritas aplikasi, sesi, API, struktur data, TLS, dan pencatatan audit.
- Logout dan kedaluwarsa sesi membatalkan sesi pada server serta membersihkan isian kredensial pada halaman login.
- Rilis menggunakan pemeriksaan integritas SHA-256, penulisan data atomik dengan cadangan, penanganan kesalahan, pembatasan permintaan, validasi masukan, perlindungan CSRF, perlindungan sesi, dan daftar berkas statis yang diizinkan.

## 23 September 2026 — v1.2.0 — Penguatan Keamanan, Audit, dan Keandalan

Rilis ini memusatkan perhatian pada pengamanan aplikasi, pencatatan kegiatan, pengelolaan sesi, dan keandalan penyimpanan data.

1. Aplikasi lokal tersedia melalui `http://localhost:1500/`, sedangkan akses dari jaringan menggunakan HTTPS pada port 1501.
2. Proses startup dipindahkan ke LaunchAgent pengguna dengan `RunAtLoad` dan `KeepAlive` sehingga server tidak bergantung pada jendela Terminal.
3. Lokasi pemasangan aplikasi dapat dipindahkan dan LaunchAgent menggunakan lokasi instalasi yang sebenarnya.
4. Kata sandi Security Engineer disimpan menggunakan PBKDF2-HMAC-SHA256 dengan 600.000 iterasi dan salt yang berbeda untuk setiap akun.
5. `security-audit.log` menyimpan kegiatan audit dalam bentuk tabel dengan nama pengguna asli untuk kebutuhan penelusuran audit, tanpa mencatat kata sandi.
6. Pencatatan audit diperluas untuk login, logout, pemeriksaan hak akses, perubahan data, menu, filter, perangkat aktif, dan informasi perangkat.
7. Pemeriksaan keamanan latar belakang ditambahkan untuk memeriksa hak akses berkas, integritas, autentikasi, sesi, API, struktur data, TLS, dan pencatatan audit.
8. Logout dan kedaluwarsa sesi membatalkan sesi pada server serta membersihkan isian nama pengguna dan kata sandi pada halaman login.
9. Rilis menggunakan pemeriksaan integritas SHA-256, penulisan data atomik dengan cadangan dan pemulihan, penanganan kesalahan yang aman, pembatasan permintaan, validasi masukan, perlindungan CSRF, perlindungan sesi, dan daftar berkas statis yang diizinkan.

## 20 Agustus 2026 — v1.1.0 — Fitur Dasar dan Executive Dashboard

Rilis awal CABEPEDES membangun dasar pengelolaan temuan dan penyajian ringkasan untuk kebutuhan pemantauan.

1. Executive Dashboard menampilkan jumlah seluruh temuan, temuan terbuka, temuan selesai, dan temuan dengan tingkat keparahan tinggi.
2. Grafik dashboard mengambil data dari sheet Calc untuk tingkat keparahan, status, sistem atau aplikasi, dan domain kontrol.
3. Data Register memuat 16 kolom sesuai workbook dan 61 data awal sebagai data dasar.
4. Pemeriksaan formula menampilkan formula Excel sumber sebagai bahan pemeriksaan.
5. Security Engineer dapat menambah, mengubah, dan menghapus data, sedangkan nomor ID Issue dibuat otomatis.
6. Data Register menyediakan pencarian serta penyaringan berdasarkan status dan tingkat keparahan.
7. Data dapat diekspor ke CSV dan dicadangkan dalam format JSON.
8. Data dapat dipertahankan dan digunakan kembali melalui mekanisme penyimpanan dan migrasi yang tersedia.
9. Perhitungan COUNTIF mengikuti pencocokan teks Excel, termasuk pola `Close*`.
10. Aplikasi menyediakan peluncur macOS dan berjalan tanpa Node.js, npm, atau kerangka kerja tambahan.

## Catatan

Riwayat di atas menjelaskan perubahan teknis dan fungsi yang diterapkan pada CABEPEDES. Pemetaan terhadap standar keamanan tidak berarti aplikasi memperoleh sertifikasi atau pengesahan pihak ketiga. Penilaian resmi tetap memerlukan pemeriksaan pada lingkungan operasional yang sebenarnya.
