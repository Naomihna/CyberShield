<?php
// includes/functions.php - Logika inti CyberShield
// Semua query memakai prepared statement (anti SQL injection).

// Angka awal dashboard, diambil dari gambar contoh CyberShield
// pada soal (124.580 paket, 118.920 diizinkan, 5.660 diblokir).
define('BASE_TOTAL', 124580);
define('BASE_ALLOWED', 118920);
define('BASE_BLOCKED', 5660);

function esc($s) {
    return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
}

function formatAngka($n) {
    return number_format((int)$n, 0, ',', '.');
}

// Cek apakah sebuah IP cocok dengan aturan (IP tunggal atau CIDR).
function ipCocok($ipAturan, $ipPaket) {
    if (strpos($ipAturan, '/') === false) {
        return $ipAturan === $ipPaket;
    }
    list($subnet, $bits) = explode('/', $ipAturan, 2);
    $ipLong = ip2long($ipPaket);
    $subLong = ip2long($subnet);
    if ($ipLong === false || $subLong === false) {
        return false;
    }
    $bits = (int)$bits;
    if ($bits === 0) {
        return true; // 0.0.0.0/0 = semua IP
    }
    $mask = -1 << (32 - $bits);
    return ($ipLong & $mask) === ($subLong & $mask);
}

// Simpan satu kejadian ke security_logs.
function catatLog(PDO $pdo, $ip, $port, $jenis, $aksi, $keterangan) {
    $st = $pdo->prepare("INSERT INTO security_logs
        (source_ip, dest_port, activity_type, action, description)
        VALUES (?, ?, ?, ?, ?)");
    $st->execute([$ip, (int)$port, $jenis, $aksi, $keterangan]);
}

// Keputusan firewall untuk satu paket.
// Urutan: blacklist dulu, lalu aturan BLOCK, lalu aturan ALLOW,
// bila tidak ada aturan yang cocok maka koneksi diizinkan.
function periksaPaket(PDO $pdo, $ip, $port) {
    $st = $pdo->prepare("SELECT reason FROM blacklist_ips WHERE ip_address = ?");
    $st->execute([$ip]);
    $hitam = $st->fetch();
    if ($hitam) {
        return ['action' => 'BLOCK', 'reason' => 'IP ada di blacklist (' . $hitam['reason'] . ')'];
    }
    $aturan = $pdo->query("SELECT * FROM firewall_rules WHERE is_active = 1 ORDER BY id ASC")->fetchAll();
    $cocokAllow = null;
    foreach ($aturan as $r) {
        if (!ipCocok($r['ip_address'], $ip)) {
            continue;
        }
        if ((int)$r['port'] !== 0 && (int)$r['port'] !== (int)$port) {
            continue;
        }
        if ($r['action'] === 'BLOCK') {
            return ['action' => 'BLOCK', 'reason' => 'Aturan: ' . $r['rule_name']];
        }
        if ($cocokAllow === null) {
            $cocokAllow = $r;
        }
    }
    if ($cocokAllow !== null) {
        return ['action' => 'ALLOW', 'reason' => 'Aturan: ' . $cocokAllow['rule_name']];
    }
    return ['action' => 'ALLOW', 'reason' => 'Tidak ada aturan yang cocok, koneksi normal diizinkan'];
}

// Angka dashboard: angka awal + log yang tercatat hari ini.
function hitungStatistik(PDO $pdo) {
    $hariIni = $pdo->query("SELECT
        COUNT(*) AS total,
        SUM(action = 'ALLOW') AS diizinkan,
        SUM(action = 'BLOCK') AS diblokir
        FROM security_logs WHERE DATE(event_time) = CURDATE()")->fetch();
    $aktif = (int)$pdo->query("SELECT COUNT(*) FROM firewall_rules WHERE is_active = 1")->fetchColumn();
    return [
        'total' => BASE_TOTAL + (int)$hariIni['total'],
        'diizinkan' => BASE_ALLOWED + (int)$hariIni['diizinkan'],
        'diblokir' => BASE_BLOCKED + (int)$hariIni['diblokir'],
        'aturan_aktif' => $aktif,
    ];
}
