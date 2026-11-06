<?php
// config/database.php - Koneksi database CyberShield (MySQL, Laragon)
// Ubah password root di sini bila MySQL di laptop memakai password.
define('DB_HOST', 'localhost');
define('DB_NAME', 'cybershield');
define('DB_USER', 'root');
define('DB_PASS', '');

function getPDO() {
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }
    $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    return $pdo;
}

// Membuat ketiga tabel bila belum ada (dipanggil sekali tiap
// halaman dimuat; aman karena memakai CREATE TABLE IF NOT EXISTS).
function ensureSchema(PDO $pdo) {
    $pdo->exec("CREATE TABLE IF NOT EXISTS firewall_rules (
        id INT AUTO_INCREMENT PRIMARY KEY,
        rule_name VARCHAR(100) NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        port INT NOT NULL DEFAULT 0,
        protocol ENUM('TCP','UDP','TCP/UDP') NOT NULL DEFAULT 'TCP',
        action ENUM('ALLOW','BLOCK') NOT NULL DEFAULT 'ALLOW',
        is_active TINYINT(1) NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB");
    $pdo->exec("CREATE TABLE IF NOT EXISTS security_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        event_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        source_ip VARCHAR(45) NOT NULL,
        dest_port INT NOT NULL,
        activity_type VARCHAR(50) NOT NULL,
        action ENUM('ALLOW','BLOCK') NOT NULL,
        description VARCHAR(255) DEFAULT NULL
    ) ENGINE=InnoDB");
    $pdo->exec("CREATE TABLE IF NOT EXISTS blacklist_ips (
        id INT AUTO_INCREMENT PRIMARY KEY,
        ip_address VARCHAR(45) NOT NULL UNIQUE,
        reason VARCHAR(100) NOT NULL DEFAULT 'Aktivitas mencurigakan',
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB");
}
