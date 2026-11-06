-- ============================================================
-- CyberShield - database.sql
-- Cara pakai (Laragon): buka HeidiSQL / phpMyAdmin, jalankan
-- file ini, atau: mysql -u root < database.sql
-- Database: cybershield
-- Tabel minimal sesuai soal: firewall_rules, security_logs,
-- blacklist_ips
-- ============================================================

CREATE DATABASE IF NOT EXISTS cybershield
  CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE cybershield;

-- ------------------------------------------------------------
-- 1) firewall_rules : aturan firewall
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS firewall_rules (
  id INT AUTO_INCREMENT PRIMARY KEY,
  rule_name VARCHAR(100) NOT NULL,
  ip_address VARCHAR(45) NOT NULL COMMENT 'IP tunggal (192.168.1.10) atau CIDR (0.0.0.0/0 = semua IP)',
  port INT NOT NULL DEFAULT 0 COMMENT '0 = semua port',
  protocol ENUM('TCP','UDP','TCP/UDP') NOT NULL DEFAULT 'TCP',
  action ENUM('ALLOW','BLOCK') NOT NULL DEFAULT 'ALLOW',
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- 2) security_logs : log keamanan
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  event_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  source_ip VARCHAR(45) NOT NULL,
  dest_port INT NOT NULL,
  activity_type VARCHAR(50) NOT NULL,
  action ENUM('ALLOW','BLOCK') NOT NULL,
  description VARCHAR(255) DEFAULT NULL
) ENGINE=InnoDB;

-- ------------------------------------------------------------
-- 3) blacklist_ips : daftar IP yang diblokir
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blacklist_ips (
  id INT AUTO_INCREMENT PRIMARY KEY,
  ip_address VARCHAR(45) NOT NULL UNIQUE,
  reason VARCHAR(100) NOT NULL DEFAULT 'Aktivitas mencurigakan',
  added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ============================================================
-- DATA AWAL
-- Aturan: 4 aturan aktif, sesuai angka pada gambar contoh
-- (Aturan Firewall Aktif = 4)
-- ============================================================
INSERT INTO firewall_rules (rule_name, ip_address, port, protocol, action, is_active) VALUES
('Web Server Internal', '192.168.1.10', 80, 'TCP', 'ALLOW', 1),
('HTTPS Aman', '192.168.1.10', 443, 'TCP', 'ALLOW', 1),
('Blokir SSH Eksternal', '0.0.0.0/0', 22, 'TCP', 'BLOCK', 1),
('Blokir Telnet', '0.0.0.0/0', 23, 'TCP', 'BLOCK', 1);

INSERT INTO blacklist_ips (ip_address, reason) VALUES
('45.134.26.10', 'Port Scan berulang'),
('185.220.101.47', 'Brute Force SSH'),
('103.75.190.22', 'Sumber serangan DDoS');

-- Log awal diberi tanggal kemarin supaya tidak ikut
-- menghitung angka dashboard hari ini. Angka dashboard
-- dihitung: 124.580 + log hari ini (lihat index.php).
INSERT INTO security_logs (event_time, source_ip, dest_port, activity_type, action, description) VALUES
(DATE_SUB(NOW(), INTERVAL 1 DAY), '192.168.1.25', 80, 'Koneksi HTTP', 'ALLOW', 'Akses web internal normal'),
(DATE_SUB(NOW(), INTERVAL 1 DAY), '192.168.1.30', 443, 'Koneksi HTTPS', 'ALLOW', 'Akses web aman'),
(DATE_SUB(NOW(), INTERVAL 1 DAY), '45.134.26.10', 22, 'Port Scan', 'BLOCK', 'IP ada di blacklist'),
(DATE_SUB(NOW(), INTERVAL 1 DAY), '203.0.113.15', 22, 'Percobaan SSH', 'BLOCK', 'Aturan Blokir SSH Eksternal'),
(DATE_SUB(NOW(), INTERVAL 1 DAY), '192.168.1.40', 53, 'Kueri DNS', 'ALLOW', 'Kueri DNS normal'),
(DATE_SUB(NOW(), INTERVAL 1 DAY), '185.220.101.47', 22, 'Brute Force', 'BLOCK', 'IP ada di blacklist'),
(DATE_SUB(NOW(), INTERVAL 1 DAY), '192.168.1.12', 443, 'Koneksi HTTPS', 'ALLOW', 'Akses web aman'),
(DATE_SUB(NOW(), INTERVAL 1 DAY), '103.75.190.22', 80, 'DDoS', 'BLOCK', 'IP ada di blacklist');
