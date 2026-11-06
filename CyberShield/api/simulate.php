<?php
// api/simulate.php - Menghasilkan satu batch paket simulasi,
// memeriksanya dengan aturan firewall + blacklist di server,
// mencatat hasilnya ke security_logs, lalu mengembalikan JSON.
header('Content-Type: application/json');
require __DIR__ . '/../config/database.php';
require __DIR__ . '/../includes/functions.php';

$mode = $_GET['mode'] ?? 'traffic';
$jumlah = ($mode === 'attack') ? 12 : 5;

$ipDalam = ['192.168.1.10', '192.168.1.12', '192.168.1.25', '192.168.1.30', '192.168.1.40'];
$ipLuar  = ['8.8.8.8', '1.1.1.1', '203.0.113.15', '198.51.100.23', '203.0.113.77'];
$ipPenyerang = ['45.134.26.10', '185.220.101.47', '103.75.190.22', '91.240.118.55'];
$portNormal = [80, 443, 53, 8080];
$portSerang = [22, 23, 3389, 80, 443];
$jenisSerang = ['DDoS', 'Port Scan', 'Brute Force', 'SQL Injection', 'Percobaan SSH'];
$jenisNormal = ['Koneksi HTTP', 'Koneksi HTTPS', 'Kueri DNS', 'Koneksi Web'];

try {
    $pdo = getPDO();
    ensureSchema($pdo);
} catch (Exception $e) {
    echo json_encode(['ok' => false, 'error' => 'Database belum terhubung. Import database.sql dulu.']);
    exit;
}

$hasil = [];
for ($i = 0; $i < $jumlah; $i++) {
    if ($mode === 'attack') {
        // Serangan: 75% dari IP penyerang, 25% dari IP luar acak.
        $ip = (mt_rand(1, 100) <= 75) ? $ipPenyerang[array_rand($ipPenyerang)] : $ipLuar[array_rand($ipLuar)];
        $port = $portSerang[array_rand($portSerang)];
        $jenis = $jenisSerang[array_rand($jenisSerang)];
    } else {
        $ip = (mt_rand(1, 100) <= 70) ? $ipDalam[array_rand($ipDalam)] : $ipLuar[array_rand($ipLuar)];
        $port = $portNormal[array_rand($portNormal)];
        $jenis = $jenisNormal[array_rand($jenisNormal)];
    }
    $cek = periksaPaket($pdo, $ip, $port);
    catatLog($pdo, $ip, $port, $jenis, $cek['action'], $cek['reason']);
    $hasil[] = [
        'waktu' => date('H:i:s'),
        'ip' => $ip,
        'port' => $port,
        'jenis' => $jenis,
        'aksi' => $cek['action'],
        'alasan' => $cek['reason'],
    ];
}

echo json_encode(['ok' => true, 'mode' => $mode, 'paket' => $hasil, 'statistik' => hitungStatistik($pdo)]);
