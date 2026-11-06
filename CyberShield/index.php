<?php
// CyberShield - index.php
// Dashboard monitoring jaringan, manajemen firewall, simulasi
// traffic & serangan, log keamanan, dan blacklist IP.
// Teknologi: PHP + MySQL (Laragon), HTML, CSS, JavaScript.
session_start();
require __DIR__ . '/config/database.php';
require __DIR__ . '/includes/functions.php';

try {
    $pdo = getPDO();
    ensureSchema($pdo);
    $dbError = null;
} catch (Exception $e) {
    $pdo = null;
    $dbError = 'Database belum terhubung. Import dulu file database.sql ke MySQL (Laragon), lalu refresh halaman ini.';
}

function redirect($page) {
    header('Location: index.php?page=' . $page);
    exit;
}
function validIpAturan($nilai) {
    if (filter_var($nilai, FILTER_VALIDATE_IP)) return true;
    if (preg_match('/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/', $nilai)) {
        list($ip, $bits) = explode('/', $nilai);
        return filter_var($ip, FILTER_VALIDATE_IP) && (int)$bits >= 0 && (int)$bits <= 32;
    }
    return false;
}

// ---------- Proses form (POST) ----------
if ($pdo && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $aksi = $_POST['aksi'] ?? '';
    try {
        if ($aksi === 'tambah_aturan') {
            $nama = trim($_POST['rule_name'] ?? '');
            $ip = trim($_POST['ip_address'] ?? '');
            $port = (int)($_POST['port'] ?? 0);
            $protokol = $_POST['protocol'] ?? 'TCP';
            $tindakan = $_POST['action'] ?? 'ALLOW';
            if ($nama === '' || !validIpAturan($ip) || $port < 0 || $port > 65535
                || !in_array($protokol, ['TCP', 'UDP', 'TCP/UDP'], true)
                || !in_array($tindakan, ['ALLOW', 'BLOCK'], true)) {
                throw new Exception('Data aturan tidak valid. Periksa nama, IP/CIDR, dan port (0-65535).');
            }
            $st = $pdo->prepare("INSERT INTO firewall_rules (rule_name, ip_address, port, protocol, action, is_active) VALUES (?, ?, ?, ?, ?, 1)");
            $st->execute([$nama, $ip, $port, $protokol, $tindakan]);
            $_SESSION['pesan'] = 'Aturan firewall "' . $nama . '" berhasil ditambahkan.';
            redirect('firewall');
        }
        if ($aksi === 'toggle_aturan') {
            $st = $pdo->prepare("UPDATE firewall_rules SET is_active = 1 - is_active WHERE id = ?");
            $st->execute([(int)$_POST['id']]);
            $_SESSION['pesan'] = 'Status aturan berhasil diubah.';
            redirect('firewall');
        }
        if ($aksi === 'hapus_aturan') {
            $st = $pdo->prepare("DELETE FROM firewall_rules WHERE id = ?");
            $st->execute([(int)$_POST['id']]);
            $_SESSION['pesan'] = 'Aturan firewall berhasil dihapus.';
            redirect('firewall');
        }
        if ($aksi === 'tambah_blacklist') {
            $ip = trim($_POST['ip_address'] ?? '');
            $alasan = trim($_POST['reason'] ?? 'Aktivitas mencurigakan');
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                throw new Exception('Alamat IP tidak valid.');
            }
            $st = $pdo->prepare("INSERT INTO blacklist_ips (ip_address, reason) VALUES (?, ?)");
            $st->execute([$ip, $alasan]);
            $_SESSION['pesan'] = 'IP ' . $ip . ' berhasil masuk blacklist.';
            redirect('blacklist');
        }
        if ($aksi === 'hapus_blacklist') {
            $st = $pdo->prepare("DELETE FROM blacklist_ips WHERE id = ?");
            $st->execute([(int)$_POST['id']]);
            $_SESSION['pesan'] = 'IP berhasil dihapus dari blacklist.';
            redirect('blacklist');
        }
        if ($aksi === 'bersihkan_log') {
            $pdo->exec("DELETE FROM security_logs");
            $_SESSION['pesan'] = 'Semua log keamanan berhasil dibersihkan.';
            redirect('log');
        }
    } catch (Exception $e) {
        $_SESSION['gagal'] = $e->getMessage();
        redirect($_GET['page'] ?? 'dashboard');
    }
}

$page = $_GET['page'] ?? 'dashboard';
$halaman = ['dashboard' => 'Dashboard', 'firewall' => 'Aturan Firewall', 'simulasi' => 'Simulasi Traffic & Serangan', 'log' => 'Log Keamanan', 'blacklist' => 'Blacklist IP & Ancaman'];
if (!isset($halaman[$page])) $page = 'dashboard';
$pesan = $_SESSION['pesan'] ?? null; $gagal = $_SESSION['gagal'] ?? null;
unset($_SESSION['pesan'], $_SESSION['gagal']);
$stat = $pdo ? hitungStatistik($pdo) : ['total' => 0, 'diizinkan' => 0, 'diblokir' => 0, 'aturan_aktif' => 0];
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberShield - <?= esc($halaman[$page]) ?></title>
<link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<header class="topbar">
    <div class="logo">🛡️ Cyber<span>Shield</span></div>
    <span class="pill on">● Firewall AKTIF</span>
    <span class="pill">TCP/IP ENGINE: ONLINE</span>
    <span class="pill">THREAT DATABASE: AKTIF</span>
    <span class="jam" id="jam"><?= esc(date('d/m/Y H:i:s')) ?></span>
</header>
<div class="layout">
    <nav class="sidebar">
        <?php foreach ($halaman as $kunci => $judul): ?>
            <a href="index.php?page=<?= $kunci ?>" class="<?= $page === $kunci ? 'aktif' : '' ?>"><?= esc($judul) ?></a>
        <?php endforeach; ?>
    </nav>
    <main class="konten">
        <?php if ($pesan): ?><div class="pesan"><?= esc($pesan) ?></div><?php endif; ?>
        <?php if ($gagal): ?><div class="pesan gagal"><?= esc($gagal) ?></div><?php endif; ?>
        <?php if ($dbError): ?><div class="pesan gagal"><?= esc($dbError) ?></div><?php endif; ?>

        <?php if ($page === 'dashboard' && $pdo): ?>
            <h1>Dashboard Monitoring</h1>
            <p class="sub">Ringkasan aktivitas jaringan dan ancaman yang diblokir CyberShield.</p>
            <div class="kartu-grid">
                <div class="kartu"><div class="label">Total Paket Diperiksa</div><div class="angka" id="stat-total"><?= formatAngka($stat['total']) ?></div><div class="ket biru">Paket yang sudah diperiksa firewall</div></div>
                <div class="kartu"><div class="label">Koneksi Diizinkan</div><div class="angka hijau" id="stat-allow"><?= formatAngka($stat['diizinkan']) ?></div><div class="ket">Tingkat kelolosan <?= number_format($stat['total'] ? $stat['diizinkan'] / $stat['total'] * 100 : 0, 1, ',', '.') ?>%</div></div>
                <div class="kartu"><div class="label">Ancaman Diblokir</div><div class="angka merah" id="stat-block"><?= formatAngka($stat['diblokir']) ?></div><div class="ket">Serangan yang berhasil dicegah</div></div>
                <div class="kartu"><div class="label">Aturan Firewall Aktif</div><div class="angka" id="stat-aturan"><?= (int)$stat['aturan_aktif'] ?></div><div class="ket">Dari <?= (int)$pdo->query("SELECT COUNT(*) FROM firewall_rules")->fetchColumn() ?> aturan yang dibuat</div></div>
            </div>
            <div class="dua-kolom">
                <div class="panel">
                    <h2>Volume Traffic Waktu Nyata</h2>
                    <p class="sub"><span class="hijau">— Diizinkan</span> &nbsp; <span class="merah">— Diblokir</span></p>
                    <canvas id="grafik" width="640" height="220" style="width:100%; height:220px;"></canvas>
                    <p class="sub" style="margin-top:8px;">Grafik terisi saat simulasi di halaman Simulasi Traffic &amp; Serangan dijalankan.</p>
                </div>
                <div class="panel">
                    <h2>Port Paling Sering Diblokir</h2>
                    <table>
                        <tr><th>Port</th><th>Jumlah Blokir</th></tr>
                        <?php $port = $pdo->query("SELECT dest_port, COUNT(*) j FROM security_logs WHERE action='BLOCK' GROUP BY dest_port ORDER BY j DESC LIMIT 5")->fetchAll();
                        if (!$port) echo '<tr><td colspan="2">Belum ada pemblokiran tercatat.</td></tr>';
                        foreach ($port as $p): ?>
                            <tr><td><?= (int)$p['dest_port'] ?></td><td><?= (int)$p['j'] ?> kali</td></tr>
                        <?php endforeach; ?>
                    </table>
                    <h2 style="margin-top:16px;">Status Sistem (Simulasi)</h2>
                    <div style="font-size:12px;">Beban CPU &nbsp;<span class="biru">18%</span></div><div class="bar-luar"><div class="bar-dalam" style="width:18%"></div></div>
                    <div style="font-size:12px;">Penggunaan Memori &nbsp;<span class="biru">42%</span></div><div class="bar-luar"><div class="bar-dalam" style="width:42%"></div></div>
                    <div style="font-size:12px;">Bandwidth &nbsp;<span class="biru">1,4 MB/detik</span></div><div class="bar-luar"><div class="bar-dalam" style="width:35%"></div></div>
                </div>
            </div>
            <div class="panel">
                <h2>Peringatan Keamanan Terkini</h2>
                <table>
                    <tr><th>Waktu</th><th>IP Asal</th><th>Port Tujuan</th><th>Jenis Serangan</th><th>Tindakan</th></tr>
                    <?php $peringatan = $pdo->query("SELECT * FROM security_logs WHERE action='BLOCK' ORDER BY event_time DESC, id DESC LIMIT 5")->fetchAll();
                    if (!$peringatan) echo '<tr><td colspan="5">Belum ada ancaman yang diblokir.</td></tr>';
                    foreach ($peringatan as $row): ?>
                        <tr><td><?= esc($row['event_time']) ?></td><td><?= esc($row['source_ip']) ?></td><td><?= (int)$row['dest_port'] ?></td><td><?= esc($row['activity_type']) ?></td><td><span class="badge block">DIBLOKIR</span></td></tr>
                    <?php endforeach; ?>
                </table>
            </div>

        <?php elseif ($page === 'firewall' && $pdo): ?>
            <h1>Manajemen Aturan Firewall</h1>
            <p class="sub">Tambah aturan baru, aktifkan atau nonaktifkan aturan, dan tentukan IP serta port yang diizinkan atau diblokir.</p>
            <div class="panel">
                <h2>Tambah Aturan Baru</h2>
                <form method="post">
                    <input type="hidden" name="aksi" value="tambah_aturan">
                    <div class="form-grid">
                        <div><label>Nama Aturan</label><input type="text" name="rule_name" placeholder="cth: Blokir SSH Eksternal" required></div>
                        <div><label>Alamat IP / CIDR</label><input type="text" name="ip_address" placeholder="192.168.1.10 atau 0.0.0.0/0" required></div>
                        <div><label>Port (0 = semua port)</label><input type="number" name="port" min="0" max="65535" value="80" required></div>
                        <div><label>Protokol</label><select name="protocol"><option>TCP</option><option>UDP</option><option>TCP/UDP</option></select></div>
                        <div><label>Tindakan</label><select name="action"><option value="ALLOW">ALLOW - Diizinkan</option><option value="BLOCK">BLOCK - Diblokir</option></select></div>
                    </div>
                    <div style="margin-top:14px;"><button type="submit">+ Tambah Aturan</button></div>
                </form>
            </div>
            <div class="panel">
                <h2>Daftar Aturan Firewall</h2>
                <table>
                    <tr><th>Nama Aturan</th><th>IP</th><th>Port</th><th>Protokol</th><th>Tindakan</th><th>Status</th><th>Aksi</th></tr>
                    <?php foreach ($pdo->query("SELECT * FROM firewall_rules ORDER BY id ASC")->fetchAll() as $r): ?>
                    <tr>
                        <td><?= esc($r['rule_name']) ?></td><td><?= esc($r['ip_address']) ?></td><td><?= (int)$r['port'] === 0 ? 'Semua' : (int)$r['port'] ?></td><td><?= esc($r['protocol']) ?></td>
                        <td><?= $r['action'] === 'BLOCK' ? '<span class="badge block">BLOCK</span>' : '<span class="badge allow">ALLOW</span>' ?></td>
                        <td><?= $r['is_active'] ? '<span class="badge allow">Aktif</span>' : '<span class="badge info">Nonaktif</span>' ?></td>
                        <td>
                            <form method="post" style="display:inline;"><input type="hidden" name="aksi" value="toggle_aturan"><input type="hidden" name="id" value="<?= (int)$r['id'] ?>"><button class="tombol-kecil abu" type="submit"><?= $r['is_active'] ? 'Nonaktifkan' : 'Aktifkan' ?></button></form>
                            <form method="post" style="display:inline;" onsubmit="return confirm('Hapus aturan ini?')"><input type="hidden" name="aksi" value="hapus_aturan"><input type="hidden" name="id" value="<?= (int)$r['id'] ?>"><button class="tombol-kecil merah" type="submit">Hapus</button></form>
                        </td>
                    </tr>
                    <?php endforeach; ?>
                </table>
            </div>

        <?php elseif ($page === 'simulasi' && $pdo): ?>
            <h1>Simulasi Traffic &amp; Serangan</h1>
            <p class="sub">Simulasi lalu lintas jaringan dan serangan. Setiap paket diperiksa di server oleh aturan firewall dan blacklist, lalu dicatat ke log keamanan.</p>
            <div class="panel">
                <p><span class="status-dot mati" id="status-dot"></span><span id="status-teks">Simulasi berhenti</span></p>
                <div style="margin-top:12px;">
                    <button id="btn-mulai" class="hijau">▶ Mulai Simulasi Traffic</button>
                    <button id="btn-berhenti" class="abu" disabled>■ Berhenti</button>
                    <button id="btn-serang" class="merah">⚠ Jalankan Simulasi Serangan</button>
                </div>
                <p class="sub" style="margin-top:10px;">Simulasi traffic mengirim 5 paket tiap 2 detik. Simulasi serangan mengirim 12 paket serangan sekaligus (DDoS, Port Scan, Brute Force, SQL Injection, percobaan SSH).</p>
            </div>
            <div class="panel">
                <h2>Volume Traffic Waktu Nyata</h2>
                <p class="sub"><span class="hijau">— Diizinkan</span> &nbsp; <span class="merah">— Diblokir</span></p>
                <canvas id="grafik" width="640" height="200" style="width:100%; height:200px;"></canvas>
            </div>
            <div class="panel">
                <h2>Lalu Lintas Jaringan (Simulasi)</h2>
                <table id="tabel-traffic">
                    <thead><tr><th>Waktu</th><th>IP Sumber</th><th>Port</th><th>Jenis Aktivitas</th><th>Status Koneksi</th><th>Alasan</th></tr></thead>
                    <tbody><tr><td colspan="6">Belum ada paket. Tekan "Mulai Simulasi Traffic" atau "Jalankan Simulasi Serangan".</td></tr></tbody>
                </table>
            </div>

        <?php elseif ($page === 'log' && $pdo): ?>
            <h1>Log Keamanan</h1>
            <p class="sub">Catatan waktu kejadian, IP sumber, port tujuan, jenis aktivitas, dan tindakan sistem.</p>
            <div class="panel">
                <form method="get" style="display:inline;">
                    <input type="hidden" name="page" value="log">
                    <select name="filter" onchange="this.form.submit()" style="width:220px;">
                        <option value="">Semua Aktivitas</option>
                        <option value="ALLOW" <?= ($_GET['filter'] ?? '') === 'ALLOW' ? 'selected' : '' ?>>Hanya yang Diizinkan</option>
                        <option value="BLOCK" <?= ($_GET['filter'] ?? '') === 'BLOCK' ? 'selected' : '' ?>>Hanya yang Diblokir</option>
                    </select>
                </form>
                <form method="post" style="display:inline; margin-left:10px;" onsubmit="return confirm('Hapus semua log keamanan?')">
                    <input type="hidden" name="aksi" value="bersihkan_log"><button class="merah" type="submit">Bersihkan Log</button>
                </form>
                <table style="margin-top:12px;">
                    <tr><th>Waktu Kejadian</th><th>IP Sumber</th><th>Port Tujuan</th><th>Jenis Aktivitas</th><th>Tindakan Sistem</th><th>Keterangan</th></tr>
                    <?php $filter = $_GET['filter'] ?? '';
                    $sql = "SELECT * FROM security_logs";
                    $params = [];
                    if ($filter === 'ALLOW' || $filter === 'BLOCK') { $sql .= " WHERE action = ?"; $params[] = $filter; }
                    $sql .= " ORDER BY event_time DESC, id DESC LIMIT 100";
                    $st = $pdo->prepare($sql); $st->execute($params);
                    $logs = $st->fetchAll();
                    if (!$logs) echo '<tr><td colspan="6">Belum ada log.</td></tr>';
                    foreach ($logs as $row): ?>
                        <tr><td><?= esc($row['event_time']) ?></td><td><?= esc($row['source_ip']) ?></td><td><?= (int)$row['dest_port'] ?></td><td><?= esc($row['activity_type']) ?></td>
                        <td><?= $row['action'] === 'BLOCK' ? '<span class="badge block">DIBLOKIR</span>' : '<span class="badge allow">DIIZINKAN</span>' ?></td><td><?= esc($row['description']) ?></td></tr>
                    <?php endforeach; ?>
                </table>
            </div>

        <?php elseif ($page === 'blacklist' && $pdo): ?>
            <h1>Blacklist IP &amp; Ancaman</h1>
            <p class="sub">Daftar IP yang masuk daftar blokir. Semua koneksi dari IP ini otomatis diblokir dan dicatat di log.</p>
            <div class="panel">
                <h2>Tambah IP ke Blacklist</h2>
                <form method="post">
                    <input type="hidden" name="aksi" value="tambah_blacklist">
                    <div class="form-grid">
                        <div><label>Alamat IP</label><input type="text" name="ip_address" placeholder="cth: 45.134.26.99" required></div>
                        <div><label>Alasan</label><input type="text" name="reason" placeholder="cth: Port Scan berulang" required></div>
                    </div>
                    <div style="margin-top:14px;"><button type="submit" class="merah">+ Tambah ke Blacklist</button></div>
                </form>
            </div>
            <div class="panel">
                <h2>Daftar IP yang Diblokir (<?= (int)$pdo->query("SELECT COUNT(*) FROM blacklist_ips")->fetchColumn() ?> IP)</h2>
                <table>
                    <tr><th>Alamat IP</th><th>Alasan</th><th>Ditambahkan</th><th>Aksi</th></tr>
                    <?php foreach ($pdo->query("SELECT * FROM blacklist_ips ORDER BY added_at DESC")->fetchAll() as $b): ?>
                    <tr><td><?= esc($b['ip_address']) ?></td><td><?= esc($b['reason']) ?></td><td><?= esc($b['added_at']) ?></td>
                    <td><form method="post" onsubmit="return confirm('Hapus IP ini dari blacklist?')"><input type="hidden" name="aksi" value="hapus_blacklist"><input type="hidden" name="id" value="<?= (int)$b['id'] ?>"><button class="tombol-kecil merah" type="submit">Hapus</button></form></td></tr>
                    <?php endforeach; ?>
                </table>
            </div>
        <?php endif; ?>
    </main>
</div>
<div id="toast"></div>
<script src="assets/js/app.js"></script>
</body>
</html>
