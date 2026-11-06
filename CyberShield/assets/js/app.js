// CyberShield - assets/js/app.js
// Simulasi lalu lintas: tiap 2 detik meminta satu batch paket ke
// api/simulate.php, lalu menampilkan hasilnya di tabel dan grafik.
// Keputusan izinkan/blokir dibuat di server (PHP), bukan di sini.
(function () {
    var timer = null;
    var riwayat = []; // {diizinkan, diblokir} per batch, untuk grafik

    function toast(pesan) {
        var t = document.getElementById('toast');
        if (!t) return;
        t.textContent = pesan;
        t.style.display = 'block';
        setTimeout(function () { t.style.display = 'none'; }, 3000);
    }

    function badge(aksi) {
        return aksi === 'BLOCK'
            ? '<span class="badge block">DIBLOKIR</span>'
            : '<span class="badge allow">DIIZINKAN</span>';
    }

    function tambahBaris(p, tabel) {
        if (!tabel) return;
        var tr = document.createElement('tr');
        tr.innerHTML = '<td>' + p.waktu + '</td><td>' + p.ip + '</td><td>' + p.port +
            '</td><td>' + p.jenis + '</td><td>' + badge(p.aksi) + '</td><td>' + p.alasan + '</td>';
        tabel.insertBefore(tr, tabel.firstChild);
        while (tabel.rows.length > 30) tabel.deleteRow(-1);
    }

    function perbaruiAngka(stat) {
        var el = function (id) { return document.getElementById(id); };
        if (el('stat-total')) el('stat-total').textContent = Number(stat.total).toLocaleString('id-ID');
        if (el('stat-allow')) el('stat-allow').textContent = Number(stat.diizinkan).toLocaleString('id-ID');
        if (el('stat-block')) el('stat-block').textContent = Number(stat.diblokir).toLocaleString('id-ID');
        if (el('stat-aturan')) el('stat-aturan').textContent = stat.aturan_aktif;
    }

    function gambarGrafik() {
        var c = document.getElementById('grafik');
        if (!c) return;
        var ctx = c.getContext('2d');
        var W = c.width, H = c.height;
        ctx.clearRect(0, 0, W, H);
        ctx.strokeStyle = '#1e293b';
        for (var g = 1; g < 4; g++) {
            ctx.beginPath(); ctx.moveTo(0, H * g / 4); ctx.lineTo(W, H * g / 4); ctx.stroke();
        }
        if (riwayat.length < 2) {
            ctx.fillStyle = '#94a3b8'; ctx.font = '13px Segoe UI';
            ctx.fillText('Tekan "Mulai Simulasi" untuk melihat grafik lalu lintas.', 12, 24);
            return;
        }
        var maks = 1;
        riwayat.forEach(function (r) { maks = Math.max(maks, r.diizinkan + r.diblokir); });
        function garis(kunci, warna) {
            ctx.strokeStyle = warna; ctx.lineWidth = 2; ctx.beginPath();
            riwayat.forEach(function (r, i) {
                var x = 10 + i * (W - 20) / 19;
                var y = H - 8 - (r[kunci] / maks) * (H - 20);
                if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
            });
            ctx.stroke();
        }
        garis('diizinkan', '#4ade80');
        garis('diblokir', '#f87171');
        // Legenda digambar di HTML di atas canvas, bukan di sini,
        // supaya tidak tertutup garis grafik.
    }

    function ambilBatch(mode) {
        fetch('api/simulate.php?mode=' + mode)
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (!data.ok) { toast(data.error || 'Simulasi gagal.'); return; }
                var tabel = document.querySelector('#tabel-traffic tbody');
                var diizinkan = 0, diblokir = 0;
                data.paket.forEach(function (p) {
                    tambahBaris(p, tabel);
                    if (p.aksi === 'BLOCK') diblokir++; else diizinkan++;
                });
                riwayat.push({ diizinkan: diizinkan, diblokir: diblokir });
                if (riwayat.length > 20) riwayat.shift();
                perbaruiAngka(data.statistik);
                gambarGrafik();
                if (mode === 'attack') {
                    toast('Simulasi serangan selesai: ' + diblokir + ' diblokir, ' + diizinkan + ' diizinkan.');
                }
            })
            .catch(function () { toast('Tidak dapat menghubungi server simulasi.'); });
    }

    function setStatus(jalan) {
        var dot = document.getElementById('status-dot');
        var teks = document.getElementById('status-teks');
        if (dot) dot.className = 'status-dot' + (jalan ? '' : ' mati');
        if (teks) teks.textContent = jalan ? 'Simulasi berjalan' : 'Simulasi berhenti';
        var bMulai = document.getElementById('btn-mulai');
        var bStop = document.getElementById('btn-berhenti');
        if (bMulai) bMulai.disabled = jalan;
        if (bStop) bStop.disabled = !jalan;
    }

    var btnMulai = document.getElementById('btn-mulai');
    if (btnMulai) btnMulai.addEventListener('click', function () {
        if (timer) return;
        setStatus(true);
        ambilBatch('traffic');
        timer = setInterval(function () { ambilBatch('traffic'); }, 2000);
    });
    var btnStop = document.getElementById('btn-berhenti');
    if (btnStop) btnStop.addEventListener('click', function () {
        clearInterval(timer); timer = null; setStatus(false);
    });
    var btnSerang = document.getElementById('btn-serang');
    if (btnSerang) btnSerang.addEventListener('click', function () {
        btnSerang.disabled = true;
        ambilBatch('attack');
        setTimeout(function () { btnSerang.disabled = false; }, 1500);
    });

    // Mode demo: buka halaman simulasi dengan ?sim=1 untuk
    // langsung menjalankan simulasi (berguna saat demo/video).
    if (new URLSearchParams(location.search).get('sim') === '1' && btnMulai) {
        setTimeout(function () { btnMulai.click(); }, 500);
    }

    // Jam di pojok kanan atas + grafik awal.
    var jamEl = document.getElementById('jam');
    if (jamEl) setInterval(function () {
        jamEl.textContent = new Date().toLocaleString('id-ID');
    }, 1000);
    gambarGrafik();
})();
