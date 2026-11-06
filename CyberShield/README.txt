CyberShield - Aplikasi Web Monitoring Jaringan & Firewall
============================================================
Dibuat dengan HTML, CSS, JavaScript (antarmuka), PHP dan MySQL
(penyimpanan server). Tema gelap, mengikuti gambar contoh pada soal.

ISI PAKET
---------
index.php                 Halaman utama (dashboard, firewall, simulasi, log, blacklist)
config/database.php       Pengaturan koneksi MySQL (host, nama database, user, password)
includes/functions.php    Logika firewall: cek blacklist, cek aturan, catat log, hitung statistik
api/simulate.php          API simulasi traffic dan serangan (dipanggil JavaScript)
assets/css/style.css      Tampilan tema gelap
assets/js/app.js          Simulasi berjalan, grafik volume traffic, tombol serangan
database.sql              Struktur database + data awal (3 tabel)
README.txt                File ini

CARA MENJALANKAN (LARAGON)
--------------------------
1. Salin folder cybershield ke C:\laragon\www\cybershield
2. Jalankan Laragon, klik Start All (Apache + MySQL harus jalan).
3. Buka HeidiSQL, buat database baru bernama cybershield,
   lalu jalankan file database.sql (atau lewat phpMyAdmin:
   http://localhost/phpmyadmin -> Import -> pilih database.sql).
   Catatan: kalau database sudah dibuat, aplikasi juga membuat
   ketiga tabel sendiri saat pertama dibuka.
4. Buka browser: http://localhost/cybershield
5. Tidak perlu login. Semua menu ada di sidebar kiri.

CARA MEMAKAI FITURNYA
---------------------
- Dashboard: angka total paket, koneksi diizinkan, ancaman
  diblokir, dan aturan aktif. Angka awal 124.580 / 118.920 /
  5.660 / 4 diambil dari gambar contoh pada soal, lalu bertambah
  mengikuti log simulasi yang tercatat hari ini.
- Aturan Firewall: isi form tambah aturan (nama, IP atau CIDR,
  port, protokol, ALLOW/BLOCK), lalu tekan Tambah Aturan.
  Tombol Aktifkan/Nonaktifkan mengubah status aturan,
  tombol Hapus menghapus aturan.
- Simulasi Traffic & Serangan: tekan Mulai Simulasi Traffic
  untuk melihat paket masuk tiap 2 detik, tekan Jalankan
  Simulasi Serangan untuk mengirim 12 paket serangan sekaligus.
  Status tiap paket (DIIZINKAN / DIBLOKIR) ditentukan server
  dari blacklist dan aturan firewall, bukan dari JavaScript.
- Log Keamanan: semua kejadian tercatat dengan waktu, IP sumber,
  port tujuan, jenis aktivitas, dan tindakan sistem. Bisa
  disaring (semua / diizinkan / diblokir) dan dibersihkan.
- Blacklist IP: tambah IP beserta alasannya, atau hapus IP
  dari daftar blokir. IP yang ada di blacklist selalu diblokir.

PENGUJIAN YANG SUDAH DILAKUKAN
------------------------------
(Detail lengkap ada di laporan dokumentasi.)
1. Koneksi diizinkan: paket dari 192.168.1.25 ke port 80
   diizinkan aturan Web Server Internal dan tercatat di log.
2. Koneksi diblokir: paket dari IP blacklist 45.134.26.10
   diblokir, dan paket ke port 22 diblokir aturan Blokir SSH.
3. Simulasi serangan: 12 paket serangan masuk log, sebagian
   besar diblokir, angka ancaman diblokir di dashboard naik.
4. Aturan baru: tambah aturan, nonaktifkan, lalu hapus -
   semuanya tersimpan di database dan langsung berpengaruh
   pada hasil simulasi.

CATATAN
-------
- Koneksi database memakai user root tanpa password, sesuai
  bawaan Laragon. Kalau MySQL di laptop memakai password,
  ubah DB_PASS di config/database.php.
- Semua query memakai prepared statement supaya aman dari
  SQL injection.
- Data simulasi (IP, port, jenis serangan) memang data contoh
  untuk keperluan demo, sesuai petunjuk soal poin B.5.
