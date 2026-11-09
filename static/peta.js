// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
// Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
/* ==========================================================================
   peta.js — Peta Ancaman Global (pandangan MAKRO) dengan HTML5 Canvas.
   Analogi: SATELIT PEMANTAU. Dari orbit, satelit melihat "proyektil" ancaman
   meluncur dari berbagai wilayah menuju markas di Nusantara.
   - Siluet dunia = inline SVG titik-titik (lihat static/index.html).
   - Trayektori = kurva Bezier kuadratik yang digambar di kanvas transparan
     di atas SVG, dianimasikan dengan requestAnimationFrame.
   - SEMUA isi (asal, status, intensitas) datang dari server lewat Peta.atur().
   Dipakai app.js: Peta.init(), Peta.atur(), Peta.tampil().
   Fase 3 (R3):
   - Bingkai digerakkan Penjadwal (penjadwal.js): hanya saat mode Makro aktif, kanvas terlihat di
     layar, dan tab sedang aktif. Tidak ada loop requestAnimationFrame sendiri lagi.
   - Bagian DIAM (lintasan, titik asal, label wilayah) digambar ke kanvas offscreen sekali per
     perubahan data/ukuran, lalu tiap bingkai cukup ditempel (drawImage).
   - Titik sepanjang kurva disimpan di tabel Float32Array (LUT): bingkai tidak lagi menghitung
     rumus Bezier, dan ekor komet = SATU path bergradasi, bukan 10 garis terpisah.
   ========================================================================== */
"use strict";

const Peta = (() => {
  // Proyeksi IDENTIK dengan tools/buat_peta.mjs (equirectangular, bujur tengah 118°BT)
  const LEBAR = 1000, TINGGI = 361, BUJUR_TENGAH = 118, LINTANG_ATAS = 75;
  const SKALA = LEBAR / 360;
  const proyeksi = (lat, lon) => [((((lon - BUJUR_TENGAH + 540) % 360) - 180) + 180) * SKALA, (LINTANG_ATAS - lat) * SKALA];

  const WARNA = { kritis: "255,92,116", waspada: "242,193,78", pantau: "242,193,78", diblokir: "122,162,214", abaikan: "120,140,170" };
  const KECEPATAN = { kritis: 0.42, waspada: 0.22, pantau: 0.16, diblokir: 0.42, abaikan: 0 };  // bagian lintasan per detik
  const lambat = matchMedia("(prefers-reduced-motion: reduce)").matches;

  let kanvas, ctx, kotak, W = 0, H = 0, s = 1, dpr = 1;
  let markas = null, serangan = new Map(), riak = [];
  let aktif = false;
  let diam = null, diamKotor = true;      // Fase 3: kanvas offscreen untuk bagian yang tidak bergerak
  const SAMPEL = 200, EKOR_SAMPEL = 24;   // resolusi LUT kurva & panjang ekor komet (dalam sampel)
  const SPRITE = {};                 // kepala proyektil bersinar, digambar sekali per warna

  function buatSprite(rgb) {
    const c = document.createElement("canvas"); c.width = c.height = 32;
    const g = c.getContext("2d"), gr = g.createRadialGradient(16, 16, 0, 16, 16, 16);
    gr.addColorStop(0, "rgba(255,255,255,1)"); gr.addColorStop(0.18, `rgba(${rgb},1)`);
    gr.addColorStop(0.45, `rgba(${rgb},.35)`); gr.addColorStop(1, `rgba(${rgb},0)`);
    g.fillStyle = gr; g.fillRect(0, 0, 32, 32);
    return c;
  }

  function ukur() {
    const r = kotak.getBoundingClientRect();
    if (!r.width) { W = 0; return; }
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = r.width; H = r.height; s = W / LEBAR;
    kanvas.width = Math.round(W * dpr); kanvas.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    diamKotor = true;
  }

  // Kurva: titik asal → titik kendali (diangkat ke "atas") → markas
  function kurva(asal) {
    const [x0, y0] = proyeksi(asal.lat, asal.lon), [x1, y1] = proyeksi(markas.lat, markas.lon);
    const jarak = Math.hypot(x1 - x0, y1 - y0);
    return { x0, y0, x1, y1, cx: (x0 + x1) / 2, cy: Math.min(y0, y1) - jarak * 0.32 };
  }
  const titikPada = (k, t) => {
    const u = 1 - t;
    return [u * u * k.x0 + 2 * u * t * k.cx + t * t * k.x1, u * u * k.y0 + 2 * u * t * k.cy + t * t * k.y1];
  };
  // Proyektil yang diblokir berhenti di "perisai" (lingkar ≈26 satuan peta dari markas)
  function batasPerisai(k) {
    let t = 1;
    while (t > 0.5) { const [x, y] = titikPada(k, t); if (Math.hypot(x - k.x1, y - k.y1) > 26) break; t -= 0.01; }
    return t;
  }

  // LUT: titik-titik kurva dihitung SEKALI per serangan (saat data datang), bukan tiap bingkai
  function buatLUT(k) {
    const lut = new Float32Array((SAMPEL + 1) * 2);
    for (let i = 0; i <= SAMPEL; i++) {
      const [x, y] = titikPada(k, i / SAMPEL);
      lut[i * 2] = x; lut[i * 2 + 1] = y;
    }
    return lut;
  }

  // Bagian diam: lintasan pudar, titik asal, label wilayah → kanvas offscreen
  function gambarDiam() {
    if (!diam) diam = document.createElement("canvas");
    diam.width = kanvas.width; diam.height = kanvas.height;
    const g = diam.getContext("2d");
    g.setTransform(dpr * s, 0, 0, dpr * s, 0, 0);          // satuan peta (0..1000)
    g.font = `${10 / s * 0.95}px ui-monospace, Menlo, monospace`;
    for (const a of serangan.values()) {
      const rgb = WARNA[a.status] || WARNA.pantau;
      g.beginPath(); g.moveTo(a.k.x0, a.k.y0); g.quadraticCurveTo(a.k.cx, a.k.cy, a.k.x1, a.k.y1);
      g.strokeStyle = `rgba(${rgb},${a.status === "abaikan" ? 0.16 : 0.22})`;
      g.lineWidth = 1 / s * 1.2;
      g.setLineDash(a.status === "abaikan" || a.jenis === "cti" ? [4, 5] : []);
      g.stroke(); g.setLineDash([]);
      g.fillStyle = `rgba(${rgb},.9)`; g.beginPath(); g.arc(a.k.x0, a.k.y0, 2.6, 0, Math.PI * 2); g.fill();
      g.fillStyle = "rgba(170,186,210,.75)"; g.fillText(a.asal.nama, a.k.x0 + 5, a.k.y0 - 5);
    }
    diamKotor = false;
  }

  // Satu bingkai. Dipanggil Penjadwal HANYA saat peta terlihat & tab aktif (dtMs sudah dibatasi 50 ms).
  function bingkai(waktu, dtMs) {
    const dt = (dtMs / 1000) * (lambat ? 0.35 : 1);
    if (diamKotor) gambarDiam();
    ctx.clearRect(0, 0, W, H);
    ctx.drawImage(diam, 0, 0, W, H);                   // bagian diam: satu tempelan
    ctx.save(); ctx.scale(s, s);                       // gambar dalam satuan peta (0..1000)
    ctx.lineCap = "round";

    for (const a of serangan.values()) {
      const rgb = WARNA[a.status] || WARNA.pantau;
      const usia = (waktu - a.lahir) / 1000;
      if (usia < 2 && a.status !== "abaikan") {        // trayektori baru: ditebalkan 2 detik pertama
        ctx.beginPath(); ctx.moveTo(a.k.x0, a.k.y0); ctx.quadraticCurveTo(a.k.cx, a.k.cy, a.k.x1, a.k.y1);
        ctx.strokeStyle = `rgba(${rgb},.45)`; ctx.lineWidth = 1.8 / s * 1.2;
        ctx.setLineDash(a.jenis === "cti" ? [4, 5] : []); ctx.stroke(); ctx.setLineDash([]);
      }
      if (!KECEPATAN[a.status]) continue;
      // Proyektil (komet): ekor = satu path bergradasi dari LUT + kepala bersinar
      const ujung = a.status === "diblokir" ? a.tPerisai : 1;
      for (let i = 0; i < a.proyektil.length; i++) {
        let t = (a.proyektil[i] += dt * KECEPATAN[a.status]);
        if (t >= ujung) {                               // tumbukan: di markas (kritis) atau di perisai (diblokir)
          const iu = Math.round(ujung * SAMPEL);
          riak.push({ x: a.lut[iu * 2], y: a.lut[iu * 2 + 1], rgb, umur: 0 });
          a.proyektil[i] = t = -Math.random() * 0.35;    // luncurkan ulang dengan jeda acak
        }
        if (t < 0) continue;
        const kepala = Math.min(SAMPEL, Math.round(t * SAMPEL)), ekor = Math.max(0, kepala - EKOR_SAMPEL);
        const hx = a.lut[kepala * 2], hy = a.lut[kepala * 2 + 1];
        if (kepala > ekor) {
          const gr = ctx.createLinearGradient(a.lut[ekor * 2], a.lut[ekor * 2 + 1], hx, hy);
          gr.addColorStop(0, `rgba(${rgb},0)`); gr.addColorStop(1, `rgba(${rgb},.85)`);
          ctx.beginPath(); ctx.moveTo(a.lut[ekor * 2], a.lut[ekor * 2 + 1]);
          for (let j = ekor + 1; j <= kepala; j++) ctx.lineTo(a.lut[j * 2], a.lut[j * 2 + 1]);
          ctx.strokeStyle = gr; ctx.lineWidth = 2.2 / s * 0.9; ctx.stroke();
        }
        const r = 9 / s * 0.9;
        ctx.drawImage(SPRITE[rgb] || (SPRITE[rgb] = buatSprite(rgb)), hx - r, hy - r, r * 2, r * 2);
      }
    }
    // Riak tumbukan
    riak = riak.filter((q) => (q.umur += dt) < 0.9);
    for (const q of riak) {
      ctx.strokeStyle = `rgba(${q.rgb},${(0.8 * (1 - q.umur / 0.9)).toFixed(3)})`;
      ctx.lineWidth = 1.4 / s;
      ctx.beginPath(); ctx.arc(q.x, q.y, 3 + q.umur * 26, 0, Math.PI * 2); ctx.stroke();
    }
    ctx.restore();
  }

  return {
    proyeksi,
    init(elKanvas, elKotak) {
      kanvas = elKanvas; kotak = elKotak; ctx = kanvas.getContext("2d");
      new ResizeObserver(() => { ukur(); Penjadwal.bangun(); }).observe(kotak);
      // Digambar hanya saat mode Makro aktif, kanvas terlihat di layar, dan tab aktif
      Penjadwal.daftar("peta", { elemen: kanvas, gambar: bingkai, boleh: () => aktif && W > 0 && markas !== null });
    },
    /** Data dari server. Trayektori lama dipertahankan agar animasi tidak "lompat". */
    atur(peta) {
      markas = peta.markas;
      const baru = new Map();
      for (const x of peta.serangan) {
        const lama = serangan.get(x.id);
        const k = kurva(x.asal);
        const jumlah = x.status === "abaikan" ? 0 : x.intensitas;
        const proyektil = lama && lama.proyektil.length === jumlah ? lama.proyektil
          : Array.from({ length: jumlah }, (_, i) => -i / Math.max(1, jumlah) - Math.random() * 0.1);
        baru.set(x.id, { ...x, k, lut: lama && lama.asal.id === x.asal.id ? lama.lut : buatLUT(k),
          tPerisai: batasPerisai(k), proyektil, lahir: lama ? lama.lahir : performance.now() });
      }
      // lapisan diam hanya digambar ulang bila ada yang berubah: serangan baru/hilang, status, atau ukuran
      const sidik = (m) => [...m.values()].map((a) => `${a.id}:${a.status}`).join("|");
      if (sidik(baru) !== sidik(serangan)) diamKotor = true;
      serangan = baru;
    },
    /** Dipanggil saat mode Makro aktif/nonaktif: animasi hanya berjalan bila terlihat. */
    tampil(ya) { aktif = ya; if (ya) { ukur(); Penjadwal.bangun(); } },   // tidak tampil = Penjadwal melewatinya
  };
})();
