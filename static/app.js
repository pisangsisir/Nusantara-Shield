// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
// Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
/* ==========================================================================
   app.js — "Pelayan" di sisi browser.
   Alur besarnya (lihat juga app/telemetri.py = dapur, app/main.py = loket):
   1. Login → dapat token (disimpan di VARIABEL, bukan localStorage).
   2. Buka SIARAN LANGSUNG: fetch("/api/telemetri/siaran") dengan token di header.
      Server terus mengirim pesan (Fase 3):
        event: keadaan  → SATU kali saat tersambung: potret utuh (peta, radar, layanan, …)
        event: tambalan → tiap detik/perubahan: HANYA selisihnya (ops) + peristiwa log baru
        event: tutup    → sesi habis / sambungan perlu disegarkan
      Setiap pesan bernomor (baris "id:"); tambalan menyebut "dari" nomor dasarnya.
   3. Tombol (picu latihan, centang langkah, pulihkan) hanya MENGIRIM PESANAN
      lewat POST. Tampilan TIDAK diubah sendiri: perubahannya datang kembali
      lewat siaran, persis seperti yang diterima browser lain.
   4. Bila siaran gagal, beralih ke POLLING (GET /api/telemetri tiap 2 detik)
      sambil terus mencoba menyambung ulang.
   v3 menambah:
   5. Panel CTI (ticker, prediksi per aset) — angka peluang dihitung SERVER.
   6. Tombol SOAR (1-click mitigation) — POST /api/soar/jalankan; hasilnya
      (kabel putus, beban turun) kembali lewat siaran seperti biasa.
   7. Sakelar Makro (peta global, peta.js) / Mikro (topologi): dua tampilan
      dari SATU potret server, jadi selalu sinkron.
   Fase 1 (pasca-audit):
   8. Label diambil dari GET /api/istilah (app/istilah.py) — tidak ada istilah tertanam di sini.
   9. Action Center punya DUA pintu: ⚡ ISOLASI (tahan 600 ms, hanya pemutus) dan pintu PEMULIHAN
      (terkunci sampai server menyatakan syarat_pulih terpenuhi). Laporan otomatis muncul
      lewat siaran setelah semua tindakan pemutus benar-benar selesai.
   Catatan keamanan: semua teks dari server dipasang dengan textContent
   (bukan innerHTML), sehingga tidak bisa menyisipkan kode (anti-XSS).
   ========================================================================== */
"use strict";

// ---------------------------------------------------------------- keadaan
const S = {
  token: null, akun: null, peran: null,
  keadaan: null, versi: -1, seqTampil: 0,
  layanan: [], batasJam: 24, insidenSebelumnya: null,
  koneksi: "mati",
  siaran: { ctrl: null, gagal: 0, timerUlang: null, timerPolling: null, segarkan: false },
  audit: [], auditTerlihat: new Set(), riwayatCari: [],
  timerJam: null, lacikLayananId: null, fokusSebelumLaci: null,
  mode: "mikro", kunciTicker: "",
  panggilanBerjalan: new Set(),                        // v5.1: panggilan cepat yang sedang "berdering"
  istilah: {},                                          // Fase 1: kamus label dari server
  idDasar: null, menungguPotret: false,                 // Fase 3: rantai tambalan (nomor dasar terakhir)
  irTerlihat: null,                                     // nomor laporan yang sudah diumumkan (toast)
  menahan: false, playbookTertunda: false,              // render ditunda selama tombol sedang ditahan
  alasanDarurat: {}, daruratTerbuka: new Set(),         // Fase 4: draf alasan isolasi darurat per insiden
  drill: null, drillHasil: null, timerDrill: null, drillJejak: "",   // drill kesiapan: state, hasil, stopwatch
};

// ---------------------------------------------------------------- Fase 1: kamus istilah (F-10)
/** Label dari server; fallback = kunci itu sendiri, sehingga label yang hilang langsung terlihat. */
const T = (kunci) => S.istilah[kunci] ?? kunci;
const kepadaManajemen = () => (S.istilah.manajemen || []).map((m) => m.jabatan).join(" & ");

async function muatIstilah() {
  try {
    const r = await fetch("/api/istilah", { cache: "no-store" });
    if (r.ok) S.istilah = await r.json();
  } catch { /* server belum siap: label jatuh ke kunci, aplikasi tetap jalan */ }
  $$("[data-istilah]").forEach((e) => { e.textContent = T(e.dataset.istilah); });
  document.title = `${T("nama_versi")} — ${T("produk")}`;
}

// ---------------------------------------------------------------- pembantu DOM
const $ = (sel, akar = document) => akar.querySelector(sel);
const $$ = (sel, akar = document) => [...akar.querySelectorAll(sel)];
const SVGNS = "http://www.w3.org/2000/svg";

/** Membuat elemen dengan atribut & anak secara aman (tanpa innerHTML). */
function el(tag, atribut = {}, ...anak) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(atribut)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "kelas") e.className = v;
    else if (k === "teks") e.textContent = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "data") Object.entries(v).forEach(([dk, dv]) => (e.dataset[dk] = dv));
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const a of anak.flat()) if (a !== null && a !== undefined) e.append(a instanceof Node ? a : String(a));
  return e;
}
function sv(tag, atribut = {}, teks) {
  const e = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(atribut)) e.setAttribute(k, v);
  if (teks != null) e.textContent = teks;
  return e;
}

const IKON = {
  hijau: "M5 12.5 10 17 19 7.5",
  kuning: "M12 8v5M12 16.5v.5M10.3 3.9 2.6 17.5A2 2 0 0 0 4.3 20.5h15.4a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z",
  merah: "M12 7v6M12 16.5v.5M12 2.5a9.5 9.5 0 1 0 0 19 9.5 9.5 0 0 0 0-19Z",
  perisai: "M12 2.5 4 5.5v6c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10v-6l-8-3ZM8.5 12l2.5 2.5 4.5-5",
  // ikon tombol SOAR (garis sederhana, inline SVG)
  potong: "M6 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM6 21a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM20 4 8.1 15.9M14.5 14.5 20 20M8.1 8.1 12 12",
  cadangan: "M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3ZM4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3",
  pulih: "M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7",
  blokir: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18ZM5.6 5.6l12.8 12.8",
  hemat: "M4 16a8 8 0 1 1 16 0M12 16l4-5M8 20h8",
  periksa: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14ZM20 20l-4-4",
  petir: "M13 2 4 14h7l-1 8 9-12h-7l1-8Z",
  kunci: "M12 2.5 4 5.5v6c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10v-6l-8-3ZM9.5 11V9.5a2.5 2.5 0 0 1 5 0V11M9 11h6v4.5H9z",
  // v4: simbol rantai komando
  orang: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8ZM4 21a8 8 0 0 1 16 0",
  telepon: "M5 4h4l2 5-2.5 1.5a11 11 0 0 0 5 5L15 13l5 2v4a2 2 0 0 1-2 2A16 16 0 0 1 3 6a2 2 0 0 1 2-2Z",
  pin: "M12 21s-7-6.2-7-11a7 7 0 1 1 14 0c0 4.8-7 11-7 11ZM12 12.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5Z",
  gedung: "M4 21V5l8-3 8 3v16M9 21v-4h6v4M8 8h.01M12 8h.01M16 8h.01M8 12h.01M12 12h.01M16 12h.01M3 21h18",
  jam: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18ZM12 7v5l3 2",
  gembok: "M6 11h12v10H6zM8.5 11V8a3.5 3.5 0 0 1 7 0v3",
  cek: "M12 2.5 4 5.5v6c0 5 3.4 8.6 8 10 4.6-1.4 8-5 8-10v-6l-8-3ZM8.5 12l2.5 2.5 4.5-5",
  rantai: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1",
  server: "M4 4h16v6H4zM4 14h16v6H4zM8 7h.01M8 17h.01",
  radio: "M5 19a10 10 0 0 1 0-14M19 5a10 10 0 0 1 0 14M8.5 15.5a5 5 0 0 1 0-7M15.5 8.5a5 5 0 0 1 0 7M12 13a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z",
  masuk: "M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M15 12H3",   // mesin deteksi aturan: upaya login
};
function ikon(nama) {
  const s = sv("svg", { viewBox: "0 0 24 24", "aria-hidden": "true", class: "ikon" });
  s.append(sv("path", { d: IKON[nama] }));
  return s;
}
const LABEL_STATUS = { hijau: "Normal", kuning: "Perlu dicek", merah: "Insiden" };
const lencana = (status) => el("span", { kelas: `lencana ${status}` }, ikon(status), LABEL_STATUS[status]);

const jamLokal = (iso) => new Date(iso).toLocaleTimeString("id-ID", { hour12: false });
const waktuLokal = (iso) => new Date(iso).toLocaleString("id-ID", { dateStyle: "short", timeStyle: "medium" });
function waktuRelatif(iso) {
  const detik = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
  if (detik < 45) return "baru saja";
  if (detik < 3600) return `${Math.round(detik / 60)} menit lalu`;
  if (detik < 86400) return `${Math.round(detik / 3600)} jam lalu`;
  return waktuLokal(iso);
}
const umurBackup = (jam) => (jam === 0 ? "baru saja" : jam < 48 ? `${jam} jam lalu` : `${Math.floor(jam / 24)} hari ${jam % 24} jam lalu`);
function relatif(m) {
  if (m === 0) return "T+0";
  const a = Math.abs(m);
  return "T−" + (a >= 1440 ? `${a / 1440} hari` : a >= 60 ? `${a / 60} jam` : `${a} mnt`);
}
const bolehUbah = () => S.peran === "operator";
/** Nilai peran di API tetap huruf kecil ("operator"); yang tampil diambil dari kamus istilah ("Operator"). */
const namaPeran = (p) => (S.istilah && S.istilah[`peran_${p}`]) || p;

/** Gambar ulang tanpa kehilangan fokus keyboard (penting saat siaran memperbarui panel). */
function denganFokus(gambar) {
  const aktif = document.activeElement, kunci = aktif?.dataset?.kunci;
  const kursor = aktif?.tagName === "TEXTAREA" ? [aktif.selectionStart, aktif.selectionEnd] : null;
  gambar();
  if (!kunci) return;
  const baru = $(`[data-kunci="${kunci}"]`);
  baru?.focus();
  if (kursor && baru?.setSelectionRange) baru.setSelectionRange(...kursor);   // Fase 4: kursor alasan tidak meloncat
}

// ---------------------------------------------------------------- notifikasi
function toast(pesan, jenis = "info") {
  const t = el("div", { kelas: `toast ${jenis}` }, el("span", { teks: pesan }));
  $("#wadah-toast").append(t);
  setTimeout(() => { t.classList.add("keluar"); setTimeout(() => t.remove(), 220); }, jenis === "galat" ? 6000 : 3800);
}
function konfirmasi(judul, pesan, teksYa = "Ya, lanjutkan") {
  const d = $("#dialog-konfirmasi");
  $("#dialog-judul").textContent = judul;
  $("#dialog-pesan").textContent = pesan;
  $("#dialog-ya").textContent = teksYa;
  d.returnValue = "";
  d.showModal();
  return new Promise((selesai) => d.addEventListener("close", () => selesai(d.returnValue === "ya"), { once: true }));
}
/** Menandai tombol sedang bekerja (cegah klik ganda). */
async function sibuk(tombol, kerja) {
  if (!tombol) return kerja();
  const asli = [...tombol.childNodes];
  tombol.disabled = true;
  tombol.replaceChildren(el("span", { kelas: "putar", "aria-hidden": "true" }), "Memproses…");
  try { return await kerja(); }
  finally { tombol.replaceChildren(...asli); tombol.disabled = false; terapkanPeran(); }
}

// ---------------------------------------------------------------- jembatan ke server (pesanan biasa)
class GalatApi extends Error { constructor(status, pesan) { super(pesan); this.status = status; } }

async function api(jalur, { metode = "GET", data, mentah = false } = {}) {
  const kepala = {};
  if (S.token) kepala.Authorization = `Bearer ${S.token}`;
  if (data !== undefined) kepala["Content-Type"] = "application/json";
  let r;
  try {
    r = await fetch(jalur, { method: metode, headers: kepala, body: data !== undefined ? JSON.stringify(data) : undefined, credentials: "same-origin", cache: "no-store" });
  } catch {
    throw new GalatApi(0, "Server tidak dapat dihubungi. Periksa apakah aplikasi masih berjalan.");
  }
  if (r.status === 401 && S.token) {
    keluarLokal("Sesi berakhir. Silakan masuk kembali.");
    throw new GalatApi(401, "Sesi berakhir");
  }
  if (!r.ok) {
    let pesan = `Gagal (${r.status})`;
    try {
      const j = await r.json();
      if (typeof j.detail === "string") pesan = j.detail;
      if (Array.isArray(j.kesalahan) && j.kesalahan.length) pesan += `: ${j.kesalahan.map((k) => k.kolom).join(", ")}`;
    } catch { /* bukan JSON */ }
    if (r.status === 429) pesan = "Terlalu banyak permintaan. Tunggu sebentar lalu coba lagi.";
    throw new GalatApi(r.status, pesan);
  }
  return mentah ? r : r.json();
}
async function coba(kerja) {
  try { return await kerja(); }
  catch (e) { if (e.status !== 401 || !S.token) toast(e.message || "Terjadi kesalahan", "galat"); return null; }
}
/** Setelah mengirim pesanan: bila siaran sedang hidup, tunggu saja (server akan mengantar).
    Bila sedang mode cadangan, ambil potret sendiri agar tampilan tidak tertinggal. */
function setelahAksi() { if (S.koneksi !== "langsung") ambilPotret(); }

// ==========================================================================
// SIARAN LANGSUNG (Server-Sent Events lewat fetch + ReadableStream)
// EventSource bawaan browser tidak bisa mengirim header Authorization; menaruh
// token di URL berisiko tercatat di log. Karena itu aliran dibaca manual.
// ==========================================================================
function aturKoneksi(status) {
  S.koneksi = status;
  const k = $("#koneksi");
  k.hidden = !S.token;
  k.dataset.status = status;
  $("#koneksi-teks").textContent = { langsung: "Siaran langsung", polling: "Cadangan: polling", menyambung: "Menyambung…", putus: "Terputus", mati: "–" }[status];
}

async function bukaSiaran() {
  if (!S.token) return;
  S.siaran.ctrl?.abort();
  const ctrl = new AbortController();
  S.siaran.ctrl = ctrl;
  if (S.koneksi !== "polling") aturKoneksi("menyambung");
  let r;
  try {
    r = await fetch("/api/telemetri/siaran", {
      headers: { Authorization: `Bearer ${S.token}`, Accept: "text/event-stream" },
      signal: ctrl.signal, cache: "no-store",
    });
  } catch { return jadwalUlang(ctrl); }
  if (r.status === 401) { keluarLokal("Sesi berakhir. Silakan masuk kembali."); return; }
  if (!r.ok || !r.body) return jadwalUlang(ctrl);

  S.siaran.gagal = 0;
  hentikanPolling();
  aturKoneksi("langsung");
  const pembaca = r.body.pipeThrough(new TextDecoderStream()).getReader();
  let sisa = "";
  try {
    for (;;) {
      const { value, done } = await pembaca.read();
      if (done) break;
      sisa += value;
      // Satu pesan SSE diakhiri baris kosong ("\n\n")
      let i;
      while ((i = sisa.indexOf("\n\n")) >= 0) {
        tanganiPesan(sisa.slice(0, i));
        sisa = sisa.slice(i + 2);
      }
    }
  } catch { /* sambungan putus atau dibatalkan */ }
  if (!ctrl.signal.aborted) jadwalUlang(ctrl);
}

/** Parser SSE sesuai spesifikasi WHATWG: data multi-baris digabung "\n", baris ":" = komentar,
    "id:" = nomor pesan (dipakai menjaga rantai tambalan). */
function tanganiPesan(blok) {
  let jenis = "message", id = null;
  const data = [];
  for (const baris of blok.replace(/\r/g, "").split("\n")) {
    if (!baris || baris.startsWith(":")) continue;                 // komentar / tetap-hidup
    const titik = baris.indexOf(":");
    const kunci = titik < 0 ? baris : baris.slice(0, titik);
    const nilai = titik < 0 ? "" : baris.slice(titik + 1).replace(/^ /, "");
    if (kunci === "event") jenis = nilai;
    else if (kunci === "data") data.push(nilai);
    else if (kunci === "id") id = Number(nilai);
  }
  if (!data.length) return;
  let isi;
  try { isi = JSON.parse(data.join("\n")); } catch { return; }
  if (jenis === "keadaan") terimaKeadaan(isi, id);
  else if (jenis === "tambalan") terimaTambalan(isi, id);
  else if (jenis === "tutup") {
    if (isi.alasan === "sesi") keluarLokal("Sesi berakhir. Silakan masuk kembali.");
    else if (isi.alasan === "segarkan") S.siaran.segarkan = true;   // penutupan terjadwal, bukan galat
  }
}

function jadwalUlang(ctrl) {
  if (S.siaran.ctrl !== ctrl || !S.token) return;
  clearTimeout(S.siaran.timerUlang);
  if (S.siaran.segarkan) {             // server meminta sambung ulang: langsung saja
    S.siaran.segarkan = false;
    S.siaran.timerUlang = setTimeout(bukaSiaran, 200);
    return;
  }
  S.siaran.gagal++;
  if (S.siaran.gagal >= 2) mulaiPolling(); else aturKoneksi("menyambung");
  // Mundur bertahap: 1, 2, 4, 8, 15 detik … agar server yang sedang sulit tidak dibanjiri
  const tunda = Math.min(15000, 1000 * 2 ** Math.min(S.siaran.gagal - 1, 4));
  S.siaran.timerUlang = setTimeout(bukaSiaran, tunda);
}

async function ambilPotret() {
  try {
    const k = await api("/api/telemetri");
    terimaKeadaan(k);
    if (S.koneksi === "putus") aturKoneksi("polling");
  } catch (e) {
    if (e.status !== 401) aturKoneksi("putus");
  }
}
function mulaiPolling() {
  if (S.siaran.timerPolling) return;
  aturKoneksi("polling");
  ambilPotret();
  S.siaran.timerPolling = setInterval(() => { if (document.visibilityState === "visible") ambilPotret(); }, 2000);
}
function hentikanPolling() { clearInterval(S.siaran.timerPolling); S.siaran.timerPolling = null; }
function tutupSiaran() {
  S.siaran.ctrl?.abort(); S.siaran.ctrl = null;
  clearTimeout(S.siaran.timerUlang); hentikanPolling();
  S.siaran.gagal = 0; S.siaran.segarkan = false;
}

// ==========================================================================
// MENYAJIKAN HIDANGAN — Fase 3 (R2): potret sekali, lalu tambalan
// ==========================================================================
/** Terapkan operasi [jenis, jalur, nilai] dari server ke store lokal (cermin app/delta.py:terapkan).
    "r" = ganti, "a" = tambah kunci, "d" = hapus kunci. Jalur ala JSON Pointer: "~1" = "/", "~0" = "~". */
function terapkanTambalan(dok, ops) {
  for (const [jenis, jalur, nilai] of ops) {
    if (jalur === "") { dok = nilai; continue; }
    const bagian = jalur.split("/").slice(1).map((b) => b.replace(/~1/g, "/").replace(/~0/g, "~"));
    const akhir = bagian.pop();
    const induk = bagian.reduce((o, b) => o[Array.isArray(o) ? Number(b) : b], dok);
    const k = Array.isArray(induk) ? Number(akhir) : akhir;
    if (jenis === "d") delete induk[k];
    else induk[k] = nilai;
  }
  return dok;
}

/** Potret utuh: dari siaran (sekali saat tersambung) atau dari polling cadangan (id = null). */
function terimaKeadaan(k, id = null) {
  S.keadaan = k;
  S.idDasar = id;                                    // dasar rantai tambalan berikutnya
  S.menungguPotret = false;
  tambahPeristiwa(k.peristiwa || []);
  gambarBagian(new Set(Object.keys(k)));             // potret utuh = semua bagian
}

/** Tambalan: hanya diterapkan bila "dari" cocok dengan potret yang kita pegang. Rantai putus
    (sambungan sempat tersendat, tab lama tidur, dsb.) → sambung ulang = server mengirim potret utuh lagi. */
function terimaTambalan(t, id) {
  if (!S.keadaan || S.idDasar == null || t.dari !== S.idDasar) {
    if (!S.menungguPotret) {                          // cukup sekali; tambalan lain diabaikan sampai potret tiba
      S.menungguPotret = true; S.idDasar = null;
      bukaSiaran();
    }
    return;
  }
  S.keadaan = terapkanTambalan(S.keadaan, t.ops);
  S.idDasar = id;
  tambahPeristiwa(t.peristiwa || []);
  gambarBagian(new Set(t.ops.map(([, j]) => j.split("/")[1])));   // bagian tingkat atas yang tersentuh
}

/** Gambar ulang HANYA panel yang datanya berubah. */
function gambarBagian(kena) {
  const k = S.keadaan, ada = (...x) => x.some((b) => kena.has(b));
  S.versi = k.versi; S.layanan = k.layanan; S.batasJam = k.batas_jam_backup;
  if (ada("postur", "kpi", "waktu", "versi")) gambarPostur(k.postur, k.kpi, k.waktu);
  if (ada("kesiapan") && k.kesiapan) gambarKesiapan(k.kesiapan);
  if (ada("topologi")) gambarTopologi(k.topologi);
  if (ada("radar")) {
    Radar.aturTitik(k.radar.titik);
    const ms = Radar.aturPutaran(k.radar.putaran_ms);
    $("#radar-putaran").textContent = `1 putaran / ${(ms / 1000).toFixed(1)} dtk · ${k.radar.titik.length} titik`;
  }
  if (ada("lalu_lintas")) gambarLaluLintas(k.lalu_lintas);
  if (ada("linimasa") && k.linimasa) gambarLinimasa(k.linimasa);
  if (ada("peta")) gambarPeta(k.peta);
  if (ada("cti")) gambarCTI(k.cti);
  if (ada("peringatan") && k.peringatan) gambarPeringatan(k.peringatan);
  if (ada("ir")) umumkanLaporanBaru(k.ir || []);
  if (ada("layanan")) beritahuInsidenBaru();
  if (ada("topologi", "peta")) perbaruiNotifSakelar();
  if (ada("layanan", "soar", "komando", "batas_jam_backup", "playbook_ringkas", "forensik")) {
    denganFokus(() => {
      if (ada("layanan", "batas_jam_backup")) { gambarTriase(); gambarPilihanSimulasi(); gambarBackup(); }
      if (S.menahan) S.playbookTertunda = true;      // jangan hancurkan tombol yang sedang ditahan
      else gambarPlaybook();
      if (S.lacikLayananId) gambarLaci();
    });
    terapkanPeran();
  }
  if (ada("versi") && !$("#panel-audit").hidden) muatAudit(true);
}

/** F-02: laporan terbit di server SETELAH semua pemutus selesai — umumkan saat ia benar-benar tiba. */
function umumkanLaporanBaru(daftar) {
  const nomor = daftar.map((ir) => ir.nomor);
  if (S.irTerlihat) {
    for (const ir of daftar) {
      if (!S.irTerlihat.has(ir.nomor)) {
        toast(`✅ ${ir.nomor} · ${T("laporan")} terkirim ke ${ir.kepada.join(" & ")}: ${ir.aset} terisolasi (${ir.tindakan.join(", ")}).`, "sukses");
      }
    }
  }
  S.irTerlihat = new Set(nomor);                    // kunjungan pertama: catat diam-diam, tanpa toast
}

/** Toast saat insiden baru muncul — termasuk yang dipicu dari jendela/akun lain. */
function beritahuInsidenBaru() {
  const kini = new Set(S.layanan.filter((l) => l.insiden).map((l) => l.id));
  if (S.insidenSebelumnya) {
    for (const id of kini) {
      if (!S.insidenSebelumnya.has(id)) {
        const l = S.layanan.find((x) => x.id === id);
        toast(`Insiden latihan dimulai: ${l.insiden.judul} di ${l.nama}.`, "peringatan");
        $(".rel-keputusan")?.scrollTo({ top: 0 });     // posko 24 jam: insiden baru → rel kembali ke Action Center
      }
    }
  }
  S.insidenSebelumnya = kini;
}

// ---------------------------------------------------------------- Executive Overview
const TEKS_POSTUR = { aman: "AMAN", waspada: "WASPADA", kritis: "KRITIS" };
function gambarPostur(postur, kpi, waktu) {
  const t = postur.tingkat;
  $("#exec").dataset.postur = t;
  $("#postur").dataset.tingkat = t;
  $("#postur-nilai").textContent = TEKS_POSTUR[t];
  $("#postur-ringkas").textContent = postur.ringkasan;
  const pil = $("#pil-postur");
  pil.hidden = false; pil.dataset.tingkat = t;
  $("#pil-postur-teks").textContent = kpi.insiden_aktif ? `${TEKS_POSTUR[t]} · ${kpi.insiden_aktif} insiden` : TEKS_POSTUR[t];
  const pecahan = (a, b) => [document.createTextNode(a), el("small", { teks: ` / ${b}` })];
  $("#kpi-sehat").replaceChildren(...pecahan(kpi.layanan_sehat, kpi.layanan_total));
  $("#kpi-host").textContent = kpi.host_terpantau;
  $("#kpi-anomali").textContent = kpi.anomali;
  $("#kpi-backup").replaceChildren(...pecahan(kpi.backup_patuh, kpi.layanan_total));
  $("#kpi-mttc").replaceChildren(...(kpi.mttc_rata == null ? [document.createTextNode("–")] : [
    document.createTextNode(lamaDetik(kpi.mttc_rata)), el("small", { teks: ` · ${kpi.mttc_n} insiden` })]));
  $("#kpi-insiden").replaceChildren(document.createTextNode(kpi.insiden_sejak),
    el("small", { teks: ` sejak ${jamMenit(kpi.posko_sejak)}` }));
  $("#cap-waktu").textContent = `server ${jamLokal(waktu)} · versi ${S.versi}`;
  document.title = kpi.insiden_aktif ? `(${kpi.insiden_aktif}) Insiden · ${T("produk")}` : `${T("nama_versi")} — ${T("produk")}`;
}

/** Nilai kesiapan siber: huruf posko + dua sub-skor + huruf per layanan. Rumus di server (telemetri.py). */
function gambarKesiapan(k) {
  $("#kesiapan").dataset.huruf = k.huruf;
  $("#kesiapan-huruf").textContent = k.huruf;
  $("#kesiapan-k").textContent = k.kerawanan;
  $("#kesiapan-i").textContent = k.insiden;
  $("#kesiapan").title = `${T("kesiapan")} ${k.huruf} (${k.nilai}/100) = nilai terendah dari Kerawanan ${k.kerawanan} dan Insiden ${k.insiden}.`
    + (k.batas ? `\n${k.batas}.` : "") + "\nA ≥ 90 · B ≥ 75 · C ≥ 60 · D ≥ 40 · E < 40";
  $("#kesiapan-layanan").replaceChildren(...k.per_layanan.map((l) => el("span", {
    kelas: "chip-huruf", "data-huruf": l.huruf,
    title: `${l.singkat}: ${l.huruf} (${l.nilai}) · Kerawanan ${l.kerawanan} · Insiden ${l.insiden}`
      + (l.rincian.peringatan_terbuka ? ` · ${l.rincian.peringatan_terbuka} peringatan terbuka` : "")
      + (l.rincian.backup_bermasalah ? " · cadangan bermasalah" : "") + (l.rincian.temuan ? " · temuan konfigurasi" : ""),
    teks: l.huruf })));
  const t = k.triase, p = $("#ringkas-triase");
  S.minAlasanTutup = t.min_alasan;
  const total = t.jumlah.selesai + t.jumlah.false_positive;
  p.hidden = !total;
  if (total) {
    const r = t.riwayat[0];
    p.replaceChildren("Triase: ", el("b", { teks: t.jumlah.selesai }), ` ${T("tutup_selesai")} · `,
      el("b", { teks: t.jumlah.false_positive }), " ", el("i", { teks: T("tutup_fp") }),
      el("small", { teks: ` · terakhir ${r.nama} oleh ${r.oleh}: "${r.alasan}"` }));
  }
}

// Tata letak peta = urusan tampilan (frontend). Daftar perangkat, kabel & status = data (backend).
const NODE_W = 128, NODE_H = 38;
const TATA_LETAK = {
  ancaman: [85, 62], internet: [85, 175], fw: [245, 175],
  portal: [415, 110], api: [415, 240], core: [590, 175], backup: [590, 290],
  dns: [860, 42], db: [860, 103], smb: [860, 164], ssh: [860, 225], rdp: [860, 286],
  genset: [860, 365],                               // Fase 6: zona kendali (OT)
};
const TOPO = { siap: false, gKabel: null, gSimpul: null, simpul: {}, kabel: {}, layanan: {} };

/** v5: klik / Enter pada titik topologi → buka Secure Command Drawer milik layanan pemiliknya. */
function klikSimpul(id) {
  const lid = TOPO.layanan[id];
  if (lid) bukaLaci(lid);
  else toast("Aset bersama — pilih titik server atau kartu aset.");
}

function siapkanTopologi() {
  const svg = $("#topo");
  const gZona = sv("g"); TOPO.gKabel = sv("g"); TOPO.gSimpul = sv("g");
  [[335, 70, 160, 210, "DMZ"], [515, 12, 475, 312, "JARINGAN INTERNAL"], [515, 334, 475, 60, "ZONA KENDALI (OT)"]].forEach(([x, y, w, h, t]) => {
    gZona.append(sv("rect", { class: "zona", x, y, width: w, height: h, rx: 14 }), sv("text", { class: "zona-label", x: x + 10, y: y + 16 }, t));
  });
  gZona.append(sv("text", { class: "zona-label", x: 20, y: 28 }, "LUAR GERBANG"));
  svg.append(gZona, TOPO.gKabel, TOPO.gSimpul);
  for (const [id, [x, y]] of Object.entries(TATA_LETAK)) {
    const g = sv("g", { class: "simpul sembunyi", transform: `translate(${x} ${y})` });
    const judul = sv("title"), t1 = sv("text", { class: "t1", x: -NODE_W / 2 + 24, y: -3 }), t2 = sv("text", { class: "t2", x: -NODE_W / 2 + 24, y: 11 });
    const risiko = sv("text", { class: "risiko", x: NODE_W / 2 - 2, y: -NODE_H / 2 - 4 });   // v3: lencana prediksi CTI
    g.append(judul, sv("rect", { x: -NODE_W / 2, y: -NODE_H / 2, width: NODE_W, height: NODE_H, rx: 9 }), sv("circle", { class: "titik", cx: -NODE_W / 2 + 13, cy: 0, r: 4 }), t1, t2, risiko);
    g.addEventListener("click", () => klikSimpul(id));
    g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); klikSimpul(id); } });
    TOPO.gSimpul.append(g);
    TOPO.simpul[id] = { g, judul, t1, t2, risiko };
  }
  TOPO.siap = true;
}
function jalurKabel(a, b) {
  const [ax, ay] = TATA_LETAK[a], [bx, by] = TATA_LETAK[b];
  if (Math.abs(ax - bx) < 10) {                     // tegak lurus
    const s = Math.sign(by - ay);
    return `M${ax} ${ay + (s * NODE_H) / 2} L${bx} ${by - (s * NODE_H) / 2}`;
  }
  const x1 = ax + NODE_W / 2, x2 = bx - NODE_W / 2, mx = (x1 + x2) / 2;  // lengkung halus
  return `M${x1} ${ay} C${mx} ${ay} ${mx} ${by} ${x2} ${by}`;
}
function gambarTopologi(topologi) {
  if (!TOPO.siap) siapkanTopologi();
  const ada = new Set();
  for (const s of topologi.simpul) {
    const ref = TOPO.simpul[s.id];
    if (!ref) continue;                              // perangkat baru tanpa tata letak: abaikan
    ada.add(s.id);
    TOPO.layanan[s.id] = s.layanan || null;
    const nmL = s.layanan && S.layanan.find((x) => x.id === s.layanan)?.nama;
    if (s.status === "isolasi" && ref.status && ref.status !== "isolasi") ref.kilat = Date.now() + 1800;
    ref.status = s.status;
    const kilatSimpul = ref.kilat > Date.now();
    ref.g.setAttribute("class", `simpul ${s.status}${SOROT.has(s.id) ? " sorot" : ""}${s.layanan ? " bisa-klik" : ""}${kilatSimpul ? " baru-isolasi" : ""}`);
    if (kilatSimpul) setTimeout(() => ref.g.classList.remove("baru-isolasi"), ref.kilat - Date.now());
    if (s.layanan) {
      ref.g.setAttribute("tabindex", "0"); ref.g.setAttribute("role", "button");
      ref.g.setAttribute("aria-label", `${s.nama} ${s.ip}, status ${s.status}. Buka profil aset ${nmL || ""}`);
    } else ["tabindex", "role", "aria-label"].forEach((a) => ref.g.removeAttribute(a));
    ref.t1.textContent = s.nama.length > 17 ? `${s.nama.slice(0, 16)}…` : s.nama;
    ref.t2.textContent = s.port ? `${s.ip}:${s.port}` : s.ip;
    ref.judul.textContent = `${s.nama} — ${s.ip}${s.port ? `:${s.port}` : ""}\n${s.catatan}${nmL ? `\nKlik: profil aset · ${nmL}` : ""}`;
    aturRisiko(ref, s.prob);
  }
  for (const [id, ref] of Object.entries(TOPO.simpul)) if (!ada.has(id)) {
    ref.g.setAttribute("class", "simpul sembunyi"); TOPO.layanan[id] = null;
    ["tabindex", "role", "aria-label"].forEach((a) => ref.g.removeAttribute(a));
  }

  const kabelAda = new Set();
  for (const k of topologi.kabel) {
    if (!TATA_LETAK[k.dari] || !TATA_LETAK[k.ke]) continue;
    const kunci = `${k.dari}-${k.ke}`;
    kabelAda.add(kunci);
    let ref = TOPO.kabel[kunci];
    if (!ref) {
      const d = jalurKabel(k.dari, k.ke);
      ref = { dasar: sv("path", { d }), arus: sv("path", { d }) };
      TOPO.gKabel.append(ref.dasar, ref.arus);
      TOPO.kabel[kunci] = ref;
    }
    // v5.1: kabel yang BARU diputus diberi kilatan sebentar agar pemutusan terlihat
    const putus = k.status === "putus";
    if (putus && ref.putus === false) ref.kilat = Date.now() + 1800;
    ref.putus = putus;
    const kilat = ref.kilat > Date.now();
    ref.dasar.setAttribute("class", `kabel ${k.jenis}${putus ? " putus" : ""}${kilat ? " baru-putus" : ""}`);
    if (kilat) setTimeout(() => ref.dasar.classList.remove("baru-putus"), ref.kilat - Date.now());
    const mati = k.status === "putus" || k.status === "diam";
    ref.arus.setAttribute("class", `arus ${mati ? "mati" : k.status}`);
    ref.dasar.style.display = ref.arus.style.display = "";
  }
  for (const [kunci, ref] of Object.entries(TOPO.kabel)) {
    if (!kabelAda.has(kunci)) ref.dasar.style.display = ref.arus.style.display = "none";
  }
}

// ---------------------------------------------------------------- CSS Gauge
function gambarLaluLintas(ll) {
  const g = $("#gauge");
  g.style.setProperty("--load", ll.beban);                    // ← satu-satunya "tuas" untuk CSS
  g.style.setProperty("--batas-waspada", ll.ambang.waspada);
  g.style.setProperty("--batas-kritis", ll.ambang.kritis);
  g.dataset.zona = ll.zona;
  g.setAttribute("aria-valuenow", Math.round(ll.beban));
  $("#g-nilai").textContent = Math.round(ll.beban);
  $("#g-zona").textContent = { aman: "Aman", waspada: "Waspada", kritis: "Kritis" }[ll.zona];
  $("#g-zona-ket").textContent = `0–${ll.ambang.waspada} aman · ${ll.ambang.waspada}–${ll.ambang.kritis} waspada · ${ll.ambang.kritis}–100 kritis`;
  $("#g-mbps").textContent = `${ll.mbps} Mbps`;
  $("#g-pps").textContent = ll.pps.toLocaleString("id-ID");
  $("#g-puncak").textContent = `${ll.puncak}%`;
  // Kabel di peta ikut: makin padat → titik arus makin cepat
  $("#topo").style.setProperty("--flow-dur", `${Math.max(0.45, 2.6 - ll.beban / 45).toFixed(2)}s`);

  // Batang paling kanan linimasa = menit yang sedang berjalan (ikut bergerak tiap detik)
  const b = LINI.batang[60];
  if (b && ll.berjalan) {
    b.style.setProperty("--h", ll.berjalan.rata);
    b.className = `berjalan ${zonaBeban(ll.berjalan.rata, ll.ambang)}`;
    b.title = `Menit berjalan (${ll.berjalan.detik} dtk) · rata-rata ${Math.round(ll.berjalan.rata)}%`;
  }
}

// ---------------------------------------------------------------- Linimasa 60 menit + pita anomali AI
const LINI = { batang: [] };
const zonaBeban = (v, a) => (v >= a.kritis ? "kritis" : v >= a.waspada ? "waspada" : "");
const jamMenit = (iso) => new Date(iso).toLocaleTimeString("id-ID", { hour: "2-digit", minute: "2-digit", hour12: false });
function lamaDetik(d) {
  if (d < 60) return `${d} dtk`;
  return `${Math.floor(d / 60)} mnt ${String(d % 60).padStart(2, "0")} dtk`;
}
function gambarLinimasa(lm) {
  const wadah = $("#linimasa-batang"), n = lm.menit.length + 1;     // 60 menit + menit berjalan
  wadah.style.setProperty("--ambang-w", lm.ambang.waspada);         // garis ambang di latar = ambang server
  wadah.style.setProperty("--ambang-k", lm.ambang.kritis);
  while (LINI.batang.length < n) { const b = el("span"); wadah.append(b); LINI.batang.push(b); }
  lm.menit.forEach((m, i) => {
    const b = LINI.batang[i];
    b.style.setProperty("--h", m.rata);
    b.className = [m.asal, zonaBeban(m.rata, lm.ambang), m.insiden ? "insiden" : ""].filter(Boolean).join(" ");
    b.title = `${jamMenit(m.akhir)} · rata-rata ${Math.round(m.rata)}% · puncak ${Math.round(m.puncak)}%`
      + (m.asal === "latihan" ? " · data latihan sebelum posko dibuka" : "")
      + (m.insiden ? " · ada insiden" : "") + (Object.keys(m.ai).length ? ` · AI: ${Object.keys(m.ai).length} aset tidak wajar` : "");
  });
  const latihan = lm.menit.filter((m) => m.asal === "latihan").length;
  const ket = $("#linimasa-ket");
  ket.hidden = !latihan;
  ket.textContent = latihan ? `${latihan} menit pertama (batang redup) adalah data latihan bangkitan sebelum posko dibuka pukul ${jamMenit(lm.posko_sejak)}; batang terang adalah beban posko per menit.` : "";

  LINI.data = lm;
  const ul = $("#pita-ai");
  if (!lm.pita.length) { ul.replaceChildren(el("li", { kelas: "kosong-kecil", teks: "Belum ada anomali AI dalam 60 menit terakhir." })); return; }
  // Yang masih berlangsung lebih dulu, lalu yang paling baru. Ringkas = 3 pita, agar tinggi panel tidak melonjak.
  const urut = [...lm.pita].sort((a, b) => (b.berlangsung - a.berlangsung) || (b.sampai - a.sampai) || (b.dari - a.dari));
  const tampil = LINI.semua ? urut : urut.slice(0, 3), sisa = urut.length - tampil.length;
  const tombolSisa = urut.length > 3 ? [el("li", {}, el("button", {
    type: "button", kelas: "tautan kecil pita-lagi", "aria-expanded": String(!!LINI.semua),
    teks: LINI.semua ? "Ringkas" : `+${sisa} aset lainnya`, onclick: () => { LINI.semua = !LINI.semua; gambarLinimasa(LINI.data); },
  }))] : [];
  ul.replaceChildren(...tampil.map((p) => {
    const jalur = el("span", { kelas: "pita-jalur", "aria-hidden": "true" }, el("i"));
    jalur.style.setProperty("--a", (p.dari / n) * 100);
    jalur.style.setProperty("--b", ((p.sampai + 1) / n) * 100);
    const menit = p.sampai - p.dari + 1;
    return el("li", {}, el("button", {
      type: "button", kelas: `pita${p.berlangsung ? " berlangsung" : ""}`,
      title: `${p.nama}: ${p.alasan}. Klik untuk melihat di topologi.`, onclick: () => lihatDiTopologi([p.aset]),
    }, el("span", { kelas: "pita-nama" }, el("b", { teks: p.nama }),
          el("small", { teks: p.berlangsung ? "berlangsung" : `${menit} mnt` })),
       jalur, el("span", { kelas: "pita-alasan", teks: p.alasan })));
  }), ...tombolSisa);
}

// ---------------------------------------------------------------- Log peringatan jaringan
const LABEL_TINGKAT = { info: "info", sedang: "sedang", tinggi: "tinggi", kritis: "kritis" };
function tambahPeristiwa(daftar) {
  const ul = $("#log-jaringan");
  for (const p of daftar) {
    if (p.seq <= S.seqTampil) continue;              // sudah pernah ditampilkan
    S.seqTampil = p.seq;
    ul.prepend(el("li", {},
      el("time", { datetime: p.waktu, teks: jamLokal(p.waktu) }),
      el("span", { kelas: `chip ${p.tingkat} ${p.jenis || ""}`, teks: p.rel_menit != null ? relatif(p.rel_menit) : p.jenis === "cti" ? "CTI" : p.jenis === "ai" ? "AI" : p.jenis === "soar" ? "SOAR" : p.jenis === "ir" ? T("laporan_singkat") : p.jenis === "bukti" ? "BUKTI" : p.jenis === "komando" ? "CALL" : p.jenis === "deteksi" ? "DETEKSI" : LABEL_TINGKAT[p.tingkat] || p.tingkat }),
      el("span", { teks: p.pesan })));
  }
  while (ul.children.length > 40) ul.lastChild.remove();
}

// ---------------------------------------------------------------- Papan triase + laci
function gambarTriase() {
  $("#batas-jam-2").textContent = S.batasJam;
  $("#grid-layanan").replaceChildren(...S.layanan.map((l) =>
    el("button", { type: "button", kelas: `layanan ${l.status}`, "data-kunci": `triase-${l.id}`,
      "aria-label": `${l.nama}: ${LABEL_STATUS[l.status]}. ${l.alasan}. Buka profil aset.`, title: l.alasan, onclick: () => bukaLaci(l.id) },
      el("span", { kelas: "nama", teks: l.singkat || l.nama }),
      lencana(l.status),
      el("span", { kelas: "meta", teks: `${l.cabang} · cadangan ${l.jam_sejak_backup} j ${l.backup_teruji ? "✓" : "✗"}` }))));
}

// ==========================================================================
// v5.1: LACI MINIMALIS — hanya Nama aset, Status, PIC teknis cabang, panggilan cepat.
// Analogi: kartu nama di samping sakelar listrik. Saat genting, operator tidak
// butuh riwayat gedung; ia butuh tahu "siapa yang harus diberi tahu" — satu tombol.
// ==========================================================================
const LABEL_STATUS_ASET = { hijau: "AMAN", kuning: "PERIKSA", merah: "KRITIS" };

function bukaLaci(id) {
  S.lacikLayananId = id;
  S.fokusSebelumLaci = document.activeElement;
  $("#laci").hidden = false; $("#laci-latar").hidden = false;
  gambarLaci();
  $("#laci-tutup").focus();
}
function tutupLaci() {
  if (!S.lacikLayananId) return;
  S.lacikLayananId = null;
  $("#laci").hidden = true; $("#laci-latar").hidden = true;
  S.fokusSebelumLaci?.focus();
}

/** Inisial avatar: buang gelar di depan/belakang ("Dr.", ", M.Kom."). */
function inisial(nama) {
  const inti = nama.split(",")[0].split(" ").filter((k) => k && !/^(dr|drs|ir|prof)\.?$/i.test(k));
  return inti.slice(0, 2).map((k) => k[0]).join("").toUpperCase();
}

function gambarLaci() {
  const l = S.layanan.find((x) => x.id === S.lacikLayananId);
  const k = S.keadaan?.komando?.[S.lacikLayananId];
  if (!l || !k) return tutupLaci();
  const pic = k.pic, sibukPanggil = S.panggilanBerjalan.has(l.id);
  const terisolasi = Boolean(k.ir);
  $("#laci-judul").textContent = l.nama;
  $("#laci").dataset.status = l.status;
  $("#laci-isi").replaceChildren(
    // 1. Status — satu kata besar
    el("div", { kelas: `status-besar ${terisolasi ? "isolasi" : l.status}`, role: "status" },
      ikon(terisolasi ? "potong" : l.status), el("b", { teks: terisolasi ? "TERISOLASI" : LABEL_STATUS_ASET[l.status] })),
    // 2. PIC teknis cabang
    el("div", { kelas: "kartu-pic" },
      el("span", { kelas: "avatar-pic", "aria-hidden": "true", teks: inisial(pic.nama) }),
      el("div", {},
        el("div", { kelas: "pic-nama" }, pic.nama, el("span", { kelas: "fiktif", teks: "fiktif" })),
        el("div", { kelas: "pic-jabatan", teks: `${pic.jabatan} · ${pic.cabang}` }))),
    // 3. Panggilan cepat — koordinasi, bukan izin
    el("button", { type: "button", kelas: `tombol-quick${l.insiden ? " genting" : ""}${sibukPanggil ? " menghubungkan" : ""}`,
      "data-ubah": "", "data-kunci": `quick-${l.id}`, "data-terkunci": sibukPanggil ? true : null,
      "aria-label": `Hubungi ${pic.jabatan} ${pic.cabang}`, onclick: () => panggilCabang(l.id) },
      sibukPanggil ? "📞 MENGHUBUNGKAN…" : T("tombol_hubungi")));
  terapkanPeran();
}

/** QUICK CALL (simulasi): beri tahu admin cabang agar tidak me-restart server yang diisolasi. */
async function panggilCabang(lid) {
  if (S.panggilanBerjalan.has(lid)) return;
  const pic = S.keadaan.komando[lid].pic;
  S.panggilanBerjalan.add(lid);
  if (S.lacikLayananId === lid) denganFokus(gambarLaci);
  toast(`📞 Menghubungi ${pic.jabatan} · ${pic.cabang}… (simulasi)`, "panggilan");
  await new Promise((r) => setTimeout(r, 1200));                // "nada sambung" simulasi
  const j = await coba(() => api("/api/komando/panggil", { metode: "POST", data: { layanan_id: lid } }));
  S.panggilanBerjalan.delete(lid);
  if (j) { toast(`✅ ${j.nama} (${j.jabatan}) dihubungi: ${j.pesan}.`, "sukses"); setelahAksi(); }
  if (S.lacikLayananId === lid) denganFokus(gambarLaci);
}

// ---------------------------------------------------------------- Simulasi & playbook
function gambarPilihanSimulasi() {
  const sel = $("#sim-layanan"), pilihan = sel.value;
  sel.replaceChildren(...S.layanan.map((l) => el("option", { value: l.id, disabled: l.insiden ? true : null, teks: l.insiden ? `${l.nama} — sedang insiden` : l.nama })));
  if (pilihan && S.layanan.some((l) => l.id === pilihan && !l.insiden)) sel.value = pilihan;
  else { const bebas = S.layanan.find((l) => !l.insiden); if (bebas) sel.value = bebas.id; }
}

async function picuLatihan(skenario, tombol) {
  const layanan_id = $("#sim-layanan").value;
  const l = S.layanan.find((x) => x.id === layanan_id);
  if (!l || l.insiden) { toast("Semua layanan sedang insiden. Pulihkan salah satu dulu.", "peringatan"); return; }
  // Hanya MENGIRIM PESANAN. Perubahan tampilan datang kembali lewat siaran.
  const gangguan_bukti = Boolean($("#sim-gangguan-bukti")?.checked);   // Fase 4: latihan agen forensik gagal
  const j = await coba(() => sibuk(tombol, () => api("/api/simulasi", { metode: "POST", data: { layanan_id, skenario, gangguan_bukti } })));
  if (j) setelahAksi();
}

// ==========================================================================
// v5.1: ACTION CENTER — satu titik keputusan per insiden.
// Teks panjang playbook diringkas jadi lencana 1–2 kata (teks lengkap di tooltip).
// ==========================================================================
const SKENARIO_PENDEK = { ransomware: "RANSOMWARE", ddos: "DDoS", backup_dimatikan: "CADANGAN MATI", sabotase_ot: "SABOTASE OT" };

function gambarPlaybook() {
  const wadah = $("#daftar-playbook");
  const aktif = S.layanan.filter((l) => l.insiden);
  $("#hitung-insiden").textContent = aktif.length ? `${aktif.length} insiden` : "";
  if (!aktif.length) {
    wadah.replaceChildren(el("div", { kelas: "siaga" }, ikon("perisai"), el("b", { teks: "SIAGA" }), el("span", { teks: "Tidak ada insiden aktif" })));
    return;
  }
  const soar = S.keadaan?.soar || { katalog: {}, antre: {}, mttc: {}, syarat_pulih: {} };
  const ringkas = S.keadaan?.playbook_ringkas || {};
  wadah.replaceChildren(...aktif.map((l) => {
    const ins = l.insiden, katalog = soar.katalog[ins.skenario] || [];
    const antre = new Set(soar.antre[l.id] || []), otomatis = new Set(katalog.map((a) => a.langkah));
    const belum = (a) => !ins.langkah_selesai[a.langkah];
    const pemutus = katalog.filter((a) => a.jenis === "pemutus");
    const pemulihan = katalog.filter((a) => a.jenis === "pemulihan");
    const sisaPemutus = pemutus.filter((a) => belum(a) && !antre.has(a.id));
    const antrePemutus = pemutus.filter((a) => antre.has(a.id));
    const ir = S.keadaan?.komando?.[l.id]?.ir, mttc = soar.mttc[l.id];
    const alasanPulih = soar.syarat_pulih?.[l.id];             // null = boleh; teks = alasan terkunci
    const pulihSelesai = pemulihan.length && pemulihan.every((a) => !belum(a));
    const jml = ins.langkah.length, selesai = ins.langkah_selesai.filter(Boolean).length;
    const label = ringkas[ins.skenario] || ins.langkah.map((t) => t.split(":")[0]);
    // Fase 4: status rantai bukti insiden ini (dari server; browser tidak pernah menghitung hash sendiri)
    const forensik = S.keadaan?.forensik || {}, f = forensik.insiden?.[l.id] || {};
    const bukti = f.bukti, drt = f.darurat, minAlasan = forensik.min_alasan || 15;
    const perluBukti = !bukti && !drt;

    // ⚡ PINTU 1 — ISOLASI: hanya tindakan pemutus, wajib ditahan 600 ms (F-04, F-09)
    const tombolIsolasi = el("button", { type: "button", kelas: `tombol-eksekusi${sisaPemutus.length ? "" : " selesai"}`, "data-ubah": "",
      "data-kunci": `eksekusi-${l.id}`, "data-terkunci": sisaPemutus.length ? null : true,
      "aria-description": sisaPemutus.length ? T("tombol_isolasi_tahan") : null },
      el("span", { kelas: "isi-tahan", "aria-hidden": "true" }),
      el("span", { kelas: "teks-eksekusi", teks: sisaPemutus.length ? T("tombol_isolasi") : antrePemutus.length ? "⏳ ISOLASI BERJALAN" : T("status_terisolasi") }),
      el("small", { teks: sisaPemutus.length ? `${perluBukti ? `${T("langkah_bukti")} → ` : ""}${sisaPemutus.length} tindakan pemutus · ${T("tombol_isolasi_tahan")}`
        : antrePemutus.length ? `${antrePemutus.length} tindakan lagi · ${T("laporan")} menyusul` : "semua tindakan pemutus selesai" }));
    if (sisaPemutus.length) pasangTahan(tombolIsolasi, () => eksekusiIsolasi(l.id, tombolIsolasi));

    // 🔒 Fase 4 — baris status bukti: nomor berita acara + sidik jari SHA-256 (lengkap di tooltip)
    const barisBukti = bukti
      ? el("div", { kelas: `status-bukti ${bukti.cocok ? "aman" : "rusak"}`, role: "status",
          title: [...bukti.barang.map((x) => `${x.nama} (${x.ukuran}) SHA-256 ${x.sha256}`),
                  `Gabungan: ${bukti.sha256}`, `Berita acara: ${bukti.hash_buku}`, `Petugas: ${bukti.petugas} · ${bukti.metode}`].join("\n") },
          el("b", { teks: bukti.cocok ? `🔒 ${bukti.nomor}` : `⚠ ${bukti.nomor}` }),
          el("span", { teks: bukti.cocok
            ? `SHA-256 ${bukti.sha256.slice(0, 12)}… · ${bukti.barang.length} berkas${bukti.susulan ? " · susulan" : ""}`
            : `SIDIK JARI TIDAK COCOK · ${bukti.periksa}` }))
      : drt
        ? el("div", { kelas: "status-bukti darurat", role: "status", title: `Alasan: ${drt.alasan}\nPetugas: ${drt.petugas}\nBerita acara: ${drt.hash_buku}` },
            el("b", { teks: "⚠ DARURAT" }), el("span", { teks: `diputus tanpa bukti oleh ${drt.petugas} · alasan tercatat` }))
        : el("div", { kelas: "status-bukti belum" },
            el("b", { teks: `○ ${T("langkah_bukti")}` }), el("span", { teks: "otomatis sebelum kabel diputus" }));

    // ⚠ EMERGENCY OVERRIDE — hanya muncul selama bukti belum ada; alasan wajib, tombol ditahan 1,5 detik
    let panelDarurat = null;
    if (perluBukti && sisaPemutus.length) {
      const draf = S.alasanDarurat[l.id] || "";
      const kurang = (t) => t.trim().replace(/\s+/g, " ").length < minAlasan;
      const hitung = el("small", { kelas: "hitung-alasan", "aria-live": "polite" });
      const tombolDarurat = el("button", { type: "button", kelas: "tombol-eksekusi tombol-darurat", "data-ubah": "",
        "data-kunci": `darurat-${l.id}`, "data-terkunci": kurang(draf) ? true : null, "aria-description": T("tombol_darurat_tahan") },
        el("span", { kelas: "isi-tahan", "aria-hidden": "true" }),
        el("span", { kelas: "teks-eksekusi", teks: T("tombol_darurat") }),
        el("small", { teks: T("tombol_darurat_tahan") }));
      const area = el("textarea", { kelas: "alasan-darurat", rows: "2", maxlength: "500", "data-kunci": `alasan-${l.id}`,
        "aria-label": "Alasan isolasi darurat",
        placeholder: `Alasan wajib (min. ${minAlasan} karakter): mengapa jaringan harus diputus sebelum bukti aman?` });
      area.value = draf;
      const segarkan = () => {
        const n = area.value.trim().replace(/\s+/g, " ").length;
        hitung.textContent = n < minAlasan ? `${n}/${minAlasan} karakter minimum` : "✓ alasan cukup · tercatat permanen";
        tombolDarurat.toggleAttribute("data-terkunci", n < minAlasan);
        tombolDarurat.disabled = n < minAlasan || !bolehUbah();
      };
      area.addEventListener("input", () => { S.alasanDarurat[l.id] = area.value; segarkan(); });
      segarkan();
      pasangTahan(tombolDarurat, () => eksekusiDarurat(l.id, tombolDarurat), LAMA_TAHAN_DARURAT_MS);
      panelDarurat = el("details", { kelas: "panel-darurat", open: S.daruratTerbuka.has(l.id) ? true : null },
        el("summary", { teks: "Bukti tidak bisa diamankan? Isolasi darurat" }), area, hitung, tombolDarurat);
      panelDarurat.addEventListener("toggle", () => {
        if (panelDarurat.open) S.daruratTerbuka.add(l.id); else S.daruratTerbuka.delete(l.id);
      });
    }
    // Setelah isolasi darurat: bukti WAJIB diamankan susulan sebelum pemulihan bisa dibuka
    const tombolBuktiSusulan = drt && !bukti
      ? el("button", { type: "button", kelas: "tombol-bukti", "data-ubah": "", "data-kunci": `bukti-${l.id}`,
          onclick: (e) => amankanBukti(l.id, e.currentTarget) }, T("tombol_amankan_bukti"))
      : null;

    // ♻ PINTU 2 — PEMULIHAN: terpisah, terkunci sampai server menyatakan syaratnya terpenuhi (F-04)
    const tombolPulih = pemulihan.length ? el("button", { type: "button", kelas: `tombol-pulih${pulihSelesai ? " selesai" : ""}`, "data-ubah": "",
      "data-kunci": `pulih-soar-${l.id}`, "data-terkunci": alasanPulih || pulihSelesai ? true : null,
      title: alasanPulih || null, onclick: (e) => pulihkanSoar(l.id, e.currentTarget) },
      el("span", { kelas: "teks-pulih", teks: pulihSelesai ? "✓ DIPULIHKAN" : T("tombol_pulihkan") }),
      el("small", { teks: pulihSelesai ? pemulihan.map((a) => a.label).join(", ") : alasanPulih ? `🔒 ${alasanPulih}` : pemulihan.map((a) => a.ket).join("; ") })) : null;

    const lencanaIr = ir
      ? el("div", { kelas: "lencana-ir", title: `${ir.insiden} · ${ir.rincian.map((r) => `${r.label} (${r.metode}, T+${r.detik} dtk)`).join(", ")}`
          + (ir.bukti ? ` · bukti ${ir.bukti.nomor}${ir.bukti.susulan ? " (adendum)" : ""}` : "")
          + (ir.darurat ? ` · ISOLASI DARURAT: ${ir.darurat.alasan}` : "") },
          ikon("cek"), el("b", { teks: ir.nomor }), el("span", { teks: `${ir.keparahan} → ${ir.kepada.join(" & ")}` }))
      : antrePemutus.length
        ? el("div", { kelas: "lencana-ir menunggu", role: "status" }, el("b", { teks: "⏳" }),
            el("span", { teks: `${T("laporan")} menunggu ${antrePemutus.length} tindakan pemutus selesai` }))
        : null;

    return el("article", { kelas: `kartu-aksi${ir ? " terisolasi" : ""}`, id: `pb-${l.id}` },
      el("div", { kelas: "judul-aksi" },
        el("b", { teks: l.singkat || l.nama }),
        el("span", { kelas: "badge-skenario", teks: SKENARIO_PENDEK[ins.skenario] || ins.skenario }),
        el("span", { kelas: "relatif", data: { iso: ins.mulai }, teks: waktuRelatif(ins.mulai) })),
      barisBukti,
      tombolIsolasi,
      panelDarurat,
      tombolBuktiSusulan,
      lencanaIr,
      // Langkah playbook sebagai lencana: klik untuk mencentang langkah manusia
      el("ol", { kelas: "lencana-langkah", "aria-label": `Langkah playbook (${selesai}/${jml})` }, ...ins.langkah.map((teks, i) => {
        const beres = ins.langkah_selesai[i];
        return el("li", {}, el("button", { type: "button", kelas: `badge-langkah${beres ? " beres" : ""}${otomatis.has(i) ? " oto" : ""}`,
          "aria-pressed": String(Boolean(beres)), title: teks, "data-ubah": "", "data-kunci": `pb-${l.id}-${i}`,
          onclick: (e) => tandaiLangkah(l.id, i, !beres, e.currentTarget) },
          el("i", { teks: beres ? "✓" : String(i + 1) }), label[i] || `Langkah ${i + 1}`));
      })),
      tombolPulih,
      el("div", { kelas: "kaki-aksi" },
        mttc ? el("span", { kelas: "mttc", teks: `⏱ MTTC ${mttc.detik} dtk` }) : el("span", { kelas: "redup kecil", teks: `${selesai}/${jml} langkah` }),
        el("button", { type: "button", kelas: "tombol halus kecil", "data-ubah": "", "data-kunci": `tutup-${l.id}`,
          "data-terkunci": selesai < jml ? true : null, title: selesai < jml ? "Selesaikan semua langkah terlebih dahulu" : null,
          teks: selesai < jml ? `${T("tombol_tutup")} (${jml - selesai} lagi)` : T("tombol_tutup"), onclick: (e) => pulihkan(l.id, e.currentTarget) })));
  }));
}

// ==========================================================================
// Fase 1 (F-09): TAHAN-UNTUK-KONFIRMASI. Tekan dan tahan 600 ms sampai bilah penuh;
// lepas lebih cepat = batal. Bekerja dengan mouse, sentuhan, dan keyboard (Spasi/Enter ditahan).
// ==========================================================================
const LAMA_TAHAN_MS = 600;
const LAMA_TAHAN_DARURAT_MS = 1500;   // Fase 4: pengecualian doktrin ditahan lebih lama dari jalur standar
function pasangTahan(tombol, kerja, ms = LAMA_TAHAN_MS) {
  let timer = null;
  tombol.style.setProperty("--lama-tahan", `${ms}ms`);
  const mulai = (e) => {
    if (tombol.disabled || timer) return;
    if (e.type === "pointerdown" && e.button !== 0) return;          // hanya tombol utama mouse
    e.preventDefault();
    S.menahan = true;
    tombol.classList.add("menahan");                                  // CSS mengisi bilah selama ms
    timer = setTimeout(() => { timer = null; selesai(); kerja(); }, ms);
  };
  const selesai = () => {
    tombol.classList.remove("menahan");
    S.menahan = false;
    if (S.playbookTertunda) { S.playbookTertunda = false; setTimeout(() => denganFokus(gambarPlaybook), 0); }
  };
  const batal = () => { if (!timer) return; clearTimeout(timer); timer = null; selesai(); };
  tombol.addEventListener("pointerdown", mulai);
  ["pointerup", "pointerleave", "pointercancel"].forEach((ev) => tombol.addEventListener(ev, batal));
  tombol.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    e.preventDefault();                                               // cegah "klik" bawaan keyboard
    if (!e.repeat) mulai(e);
  });
  tombol.addEventListener("keyup", (e) => { if (e.key === "Enter" || e.key === " ") batal(); });
  tombol.addEventListener("blur", batal);
  tombol.addEventListener("contextmenu", (e) => e.preventDefault()); // tekan lama di layar sentuh
}

/** ⚡ ISOLASI — hanya dipanggil setelah tombol ditahan penuh. Server menjalankan tindakan PEMUTUS saja;
    laporan ke manajemen menyusul lewat siaran begitu semuanya selesai (lihat umumkanLaporanBaru). */
async function eksekusiIsolasi(lid, tombol) {
  if (S.mode !== "mikro") aturMode("mikro");                   // tampilkan topologi agar pemutusan terlihat
  let j = null;
  try { j = await sibuk(tombol, () => api("/api/soar/jalankan", { metode: "POST", data: { layanan_id: lid, aksi: "isolasi" } })); }
  catch (e) {
    if (e.status !== 401) toast(e.message, "galat");
    // Fase 4: bukti gagal diamankan → buka panel isolasi darurat agar operator tidak mencari-cari
    if (e.status === 409 && e.message.includes(T("tombol_darurat"))) { S.daruratTerbuka.add(lid); denganFokus(gambarPlaybook); }
    return;
  }
  if (!j) return;
  if (j.ir) {
    S.irTerlihat?.add(j.ir.nomor);                             // sudah diumumkan di sini, jangan dobel
    toast(`✅ Isolasi selesai. ${j.ir.nomor} · ${T("laporan")} terkirim ke ${j.ir.kepada.join(" & ")}.`, "sukses");
  } else {
    toast(`⚡ Isolasi berjalan (${j.dijadwalkan.length} tindakan pemutus). ${T("laporan")} terbit setelah semuanya selesai.`, "info");
  }
  setelahAksi();
}

/** Isolasi darurat (emergency override) — dipanggil setelah tombol ditahan 1,5 detik. Server menolak bila alasan kurang
    atau bukti sebenarnya sudah aman; alasan dicatat di buku rantai bukti, log audit, dan laporan. */
async function eksekusiDarurat(lid, tombol) {
  const alasan = (S.alasanDarurat[lid] || "").trim();
  if (S.mode !== "mikro") aturMode("mikro");
  const j = await coba(() => sibuk(tombol, () => api("/api/soar/darurat", { metode: "POST", data: { layanan_id: lid, alasan } })));
  if (!j) return;
  delete S.alasanDarurat[lid];
  S.daruratTerbuka.delete(lid);
  toast(`⚠ Isolasi darurat dijalankan. Alasan tercatat di ${T("buku_bukti")}. Bukti wajib diamankan susulan sebelum memulihkan.`, "peringatan");
  setelahAksi();
}

/** 🔒 Bukti susulan (setelah isolasi darurat): server menyalin, menghitung SHA-256, dan mencatat berita acara. */
async function amankanBukti(lid, tombol) {
  const j = await coba(() => sibuk(tombol, () => api("/api/soar/jalankan", { metode: "POST", data: { layanan_id: lid, aksi: "amankan_bukti" } })));
  if (!j) return;
  toast(`🔒 Bukti diamankan dan tercatat di ${T("buku_bukti")}.`, "sukses");
  setelahAksi();
}

/** PEMULIHAN — pintu terpisah. Server tetap memeriksa ulang syaratnya (409 + alasan bila belum). */
async function pulihkanSoar(lid, tombol) {
  const j = await coba(() => sibuk(tombol, () => api("/api/soar/jalankan", { metode: "POST", data: { layanan_id: lid, aksi: "pulihkan" } })));
  if (!j) return;
  toast("♻ Pemulihan dijalankan. Centang langkah terakhir lalu tutup insiden.", "sukses");
  setelahAksi();
}

async function tandaiLangkah(id, indeks, selesai, tombol) {
  const j = await coba(() => sibuk(tombol, () => api("/api/playbook/langkah", { metode: "POST", data: { layanan_id: id, indeks, selesai } })));
  if (j) setelahAksi();
}
async function pulihkan(id, tombol) {
  const j = await coba(() => sibuk(tombol, () => api("/api/pulihkan", { metode: "POST", data: { layanan_id: id } })));
  if (!j) return;
  toast(`${j.nama} pulih dan kembali normal. Kerja bagus!`);
  setelahAksi();
}

/** Akun pengamat: semua kontrol yang mengubah data dinonaktifkan. */
function terapkanPeran() {
  const boleh = bolehUbah();
  $("#tab-akun").hidden = !boleh;                         // Fase 5: dasbor akun hanya untuk operator
  if (!boleh && !$("#panel-akun").hidden) pilihTab("indikator");
  const adaBebas = S.layanan.some((l) => !l.insiden);
  $$("[data-ubah]").forEach((b) => {
    b.disabled = !boleh || b.hasAttribute("data-terkunci") || (b.classList.contains("opsi-skenario") && !adaBebas);
  });
  $("#sim-layanan").disabled = !boleh;
  $$(".catatan-peran").forEach((p) => { p.hidden = boleh; });
}

// ==========================================================================
// v3: THREAT INTELLIGENCE (CTI) — radio satpam & prediksi
// ==========================================================================
function aturRisiko(ref, prob) {
  const tampil = prob != null && prob >= 30;
  ref.risiko.textContent = tampil ? `risiko ${prob}%` : "";
  ref.risiko.setAttribute("class", `risiko${prob >= 75 ? " tinggi" : ""}`);
}

let kunciPrediksi = "";
function gambarCTI(cti) {
  // Lencana "risiko %" di topologi ikut diperbarui tiap detik (berita memudar)
  const prob = new Map(cti.prediksi.map((p) => [p.id, p.persen]));
  for (const [id, ref] of Object.entries(TOPO.simpul)) aturRisiko(ref, prob.get(id));
  $("#cti-berikut").textContent = `${cti.berita.length} berita aktif · berikutnya ≈${cti.berikut_detik} dtk`;

  if (cti.ai) {
    const a = cti.ai;
    $("#status-ai").textContent = `AI lokal · ${a.model} · ${a.pohon} pohon · ${a.fitur} ciri · luring · `
      + `nilai 9 aset ${koma(a.skor_ms, 1)} ms · ${a.aset_anomali ? `${a.aset_anomali} aset tidak wajar` : "semua lalu lintas wajar"}`;
    $("#status-ai").classList.toggle("waspada", a.aset_anomali > 0);
  }
  const ambang = Math.round(cti.ambang_proaktif * 100);
  const kunci = JSON.stringify(cti.prediksi.map((p) => [p.id, p.persen, p.diperketat, p.ai && p.ai.skor, (p.deteksi || []).map((d) => d.alasan)])) + S.peran;
  if (kunci !== kunciPrediksi) {                    // gambar ulang hanya bila angkanya berubah
    kunciPrediksi = kunci;
    denganFokus(() => {
      const ul = $("#daftar-prediksi");
      if (!cti.prediksi.length) {
        ul.replaceChildren(el("li", { kelas: "kosong-kecil", teks: "Belum ada berita yang cocok dengan aset kita. Semua aset pada risiko dasar." }));
        return;
      }
      ul.replaceChildren(...cti.prediksi.map((p) => {
        const bar = el("div", { kelas: "bar-peluang", "data-tingkat": p.tingkat, title: `garis tegak = ambang waspada ${ambang}%` }, el("i"));
        bar.style.setProperty("--p", p.persen);
        bar.style.setProperty("--ambang", ambang);
        return el("li", { kelas: p.proaktif ? "waspada" : null },
          el("div", { kelas: "aset" }, p.nama, el("small", { teks: `${p.ip}:${p.port} · sumber ${p.sumber.join(", ")}` }),
            p.ai ? el("small", { kelas: "alasan-ai", teks: `AI lokal · skor ${koma(p.ai.skor, 2)} · ${p.ai.alasan}` }) : null,
            ...(p.deteksi || []).map((d) => el("small", { kelas: `alasan-det ${d.keparahan}`, teks: `${d.nama} · ${d.alasan}` }))),
          el("div", { kelas: `persen ${p.tingkat.replace(" ", "-")}`, teks: `${p.persen}%` }),
          bar,
          el("div", { kelas: "baris-bawah" },
            el("span", { kelas: p.diperketat ? "diperketat" : "",
              teks: p.diperketat ? "✓ diperketat (paparan −70%)" : p.proaktif ? `peluang ${p.tingkat} → dinaikkan ke WASPADA` : `peluang ${p.tingkat} → dipantau` }),
            el("span", { kelas: "tombol-baris" },
              p.diperketat ? null : el("button", { type: "button", kelas: "tombol kecil", "data-ubah": "", "data-kunci": `perketat-${p.id}`,
                title: "SOAR proaktif: tutup akses dari luar & pasang pembaruan sebelum diserang", onclick: (e) => perketatAset(p.id, e.currentTarget) }, ikon("kunci"), "Perketat"),
              p.proaktif ? el("button", { type: "button", kelas: "tombol kecil halus", "data-ubah": "", "data-kunci": `tutup-${p.id}`,
                title: "Triase: tutup peringatan ini dengan alasan tertulis (tercatat permanen)", onclick: () => bukaTutup(p) }, T("tombol_tutup_peringatan")) : null)));
      }));
    });
    terapkanPeran();
  }

  $("#daftar-berita").replaceChildren(...(cti.berita.length ? cti.berita.map((b) => {
    const ttl = el("div", { kelas: "ttl", title: "kesegaran berita" }, el("i"));
    ttl.firstChild.style.setProperty("--sisa", Math.round(b.kesegaran * 100));
    const cocok = b.korelasi.length;
    return el("article", { kelas: `berita${cocok ? "" : " abaikan"}` },
      el("div", { kelas: "kepala-berita" }, el("span", { teks: `${b.id} · ${b.sumber}` }), el("span", { teks: `${b.sisa_detik} dtk` })),
      el("p", { kelas: "judul-berita", teks: b.judul }),
      el("div", { kelas: "korelasi-berita", teks: cocok ? `Cocok: ${b.korelasi.map((k) => `${k.nama} ${k.persen}%`).join(" · ")}` : `Tidak relevan: port ${b.port.join(", ")} tidak ada di inventaris` }),
      ttl);
  }) : [el("div", { kelas: "kosong-kecil", teks: "Radio sedang hening." })]));
  if (cti.riwayat) gambarTicker(cti.riwayat);
}

function gambarTicker(riwayat) {
  const kunci = riwayat.map((r) => r.id + r.terbit).join("|");
  if (!riwayat.length || kunci === S.kunciTicker) return;   // jangan ulang animasi tanpa berita baru
  S.kunciTicker = kunci;
  const item = (r, salinan) => el("span", { kelas: "ticker-item", "aria-hidden": salinan ? "true" : null },
    el("b", { teks: `[${r.id}]` }), `${r.judul} · ${r.sumber}`,
    el("span", { kelas: `korelasi${r.korelasi.length ? "" : " abaikan"}`,
      teks: r.korelasi.length ? `→ ${r.korelasi.map((k) => `${k.nama} ${k.persen}%`).join(", ")}` : "→ tidak relevan" }));
  const isi = $("#ticker-isi");
  isi.replaceChildren(...riwayat.map((r) => item(r, false)), ...riwayat.map((r) => item(r, true)));  // digandakan: putaran mulus
  isi.style.setProperty("--durasi-ticker", `${Math.max(30, riwayat.length * 14)}s`);
}

/** Angka desimal gaya Indonesia: 0.674 → "0,67". */
const koma = (x, d) => Number(x).toFixed(d).replace(".", ",");

async function latihanAI(tombol, aset_id) {
  const j = await coba(() => sibuk(tombol, () => api("/api/ai/latihan", { metode: "POST", data: { aset_id } })));
  if (!j) return;
  toast(j.anomali ? `AI lokal: lalu lintas tidak wajar (skor ${koma(j.skor, 2)}) — ${j.alasan}. Peluang serangan ${j.persen}%.`
    : "AI lokal: pola latihan masih dinilai wajar.", j.anomali ? "peringatan" : "info");
  setelahAksi();
}

// mesin deteksi aturan: putar peristiwa mentah sintetis; temuan lahir dari aturan di server (app/deteksi.py)
async function latihanDeteksi(tombol, jenis) {
  const j = await coba(() => sibuk(tombol, () => api("/api/deteksi/latihan", { metode: "POST", data: { jenis } })));
  if (!j) return;
  toast(`Latihan deteksi: ${j.peristiwa} peristiwa mentah diputar selama ≈${Math.round(j.durasi_detik)} dtk. Perhatikan Peringatan terbaru dan Prediksi CTI + AI.`);
  setelahAksi();
}

// Fase 3: impor log ASLI secara luring. Berkas dibaca di browser lalu dikirim sebagai teks ke server sendiri;
// tidak ada yang keluar dari jaringan satuan. Server menilainya dengan aturan yang sama dengan latihan.
const MAKS_BERKAS_IMPOR = 2_000_000;
async function imporLog(berkas) {
  if (!berkas) return;
  if (berkas.size > MAKS_BERKAS_IMPOR) { toast("Berkas terlalu besar (maks. ≈2 MB). Pecah berkasnya lalu impor bertahap.", "galat"); return; }
  const isi = await berkas.text();
  const tombol = $("#tombol-impor-log");
  const j = await coba(() => sibuk(tombol, () => api("/api/deteksi/impor", { metode: "POST", data: { nama: berkas.name, isi } })));
  if (!j) return;
  const naik = j.waspada.length ? ` ${j.waspada.join(", ")} naik ke WASPADA.` : "";
  toast(`Impor «${j.berkas}» (${j.format}): ${j.dikenali} dari ${j.baris} baris dikenali → ${j.temuan.length} temuan.${naik}`,
    j.temuan.length ? "peringatan" : "info");
  setelahAksi();
}

// Daftar peringatan terbaru: label status disusun SERVER dari data sebenarnya (Operator, nomor bukti, aturan).
const IKON_PERINGATAN = { deteksi: "masuk", ai: "petir", insiden: "merah", pulih: "pulih" };
const LABEL_KEPARAHAN = { kritis: "Kritis", tinggi: "Tinggi", sedang: "Sedang", info: "Info" };
/** Peringatan terbaru = tabel lebar penuh. Judul server berpola "<peringatan> · <aset>", dipecah jadi dua kolom. */
function gambarPeringatan(daftar) {
  const tb = $("#daftar-peringatan");
  const terbuka = daftar.filter((x) => x.kelas === "terbuka").length;
  $("#hitung-peringatan").textContent = daftar.length ? `${daftar.length} terbaru · ${terbuka} perlu tindakan` : "–";
  if (!daftar.length) { tb.replaceChildren(el("tr", { kelas: "kosong" }, el("td", { colspan: 5, teks: "Belum ada peringatan." }))); return; }
  tb.replaceChildren(...daftar.map((x) => {
    const i = x.judul.lastIndexOf(" · ");
    const nama = i > 0 ? x.judul.slice(0, i) : x.judul, aset = i > 0 ? x.judul.slice(i + 3) : "–";
    return el("tr", { kelas: `peringatan ${x.kelas}` },
      el("td", { kelas: "kol-keparahan", "data-label": "Keparahan" },
        el("span", { kelas: `chip ${x.keparahan}`, teks: LABEL_KEPARAHAN[x.keparahan] || x.keparahan })),
      el("td", { kelas: "kol-peringatan", "data-label": "Peringatan" },
        ikon(x.aturan === "pindai_port" ? "periksa" : IKON_PERINGATAN[x.jenis] || "kuning"),
        el("div", { kelas: "isi-peringatan" }, el("b", { teks: nama }),
          x.rincian ? el("small", { teks: x.rincian, title: x.rincian }) : null,
          // Fase 2: teknik MITRE ATT&CK (pemetaan mandiri; tabel di app/mitre.py) dan label batasan sumber data
          (x.mitre || []).length ? el("span", { kelas: "baris-mitre", "aria-label": "Teknik MITRE ATT&CK" },
            ...x.mitre.map((m) => el("span", { kelas: `tag-mitre${m.matriks === "ICS" ? " ics" : ""}`, teks: m.id,
              title: `MITRE ATT&CK ${m.matriks === "ICS" ? "for ICS" : "Enterprise"}: ${m.id} ${m.nama}` }))) : null,
          x.sumber_data ? el("small", { kelas: "sumber-data", teks: x.sumber_data, title: x.sumber_data }) : null)),
      el("td", { kelas: "kol-aset", "data-label": "Aset", teks: aset }),
      el("td", { kelas: "kol-status status-peringatan", "data-label": "Status", teks: x.status }),
      el("td", { kelas: "kol-waktu", "data-label": "Waktu" }, el("time", { datetime: x.waktu, teks: jamLokal(x.waktu) })));
  }));
}

async function siarkanBerita(tombol, beritaId) {
  const data = beritaId ? { berita_id: beritaId } : {};
  const j = await coba(() => sibuk(tombol, () => api("/api/cti/siarkan", { metode: "POST", data })));
  if (!j) return;
  toast(`Radio CTI: ${j.id} disiarkan${j.korelasi.length ? ` — cocok dengan ${j.korelasi.map((k) => k.nama).join(", ")}` : " — tidak relevan bagi aset kita"}.`,
    j.korelasi.length ? "peringatan" : "info");
  setelahAksi();
}

// ==========================================================================
// v3: SOAR — tombol tindakan cepat (1-click mitigation)
// ==========================================================================
async function perketatAset(aset_id, tombol) {
  const j = await coba(() => sibuk(tombol, () => api("/api/soar/perketat", { metode: "POST", data: { aset_id } })));
  if (j) { toast("Pengerasan diterapkan. Peluang serangan aset ini turun."); setelahAksi(); }
}

// ==========================================================================
// TRIASE: penutupan peringatan WASPADA beralasan (hanya Operator; server tetap memeriksa ulang)
// ==========================================================================
function bukaTutup(p) {
  S.tutupAset = p.id;
  $("#tutup-aset").textContent = p.nama;
  $("#tutup-info").textContent = `${p.ip}:${p.port} · peluang ${p.persen}% · sumber ${p.sumber.join(", ")}. `
    + "Sumber-sumber ini tidak lagi menaikkan aset ke WASPADA; berita dan penilaian AI tetap tercatat. Bukti baru membuka peringatan lagi.";
  $("#form-tutup").reset();
  hitungAlasanTutup();
  $("#dialog-tutup").showModal();
}
function hitungAlasanTutup() {
  const n = $("#tutup-alasan").value.trim().length, min = S.minAlasanTutup || 15;
  $("#tutup-hitung").textContent = n < min ? `${n}/${min} karakter minimum` : "✓ alasan cukup · tercatat permanen";
  return n >= min;
}
async function kirimTutup(e) {
  if (e.submitter?.value !== "ya") return;               // Batal: biarkan dialog menutup
  e.preventDefault();
  const status = $("#form-tutup").querySelector("input[name=status-tutup]:checked")?.value;
  if (!status) { toast("Pilih status penutupan lebih dulu.", "galat"); return; }
  if (!hitungAlasanTutup()) { toast("Alasan terlalu pendek.", "galat"); $("#tutup-alasan").focus(); return; }
  const alasan = $("#tutup-alasan").value.trim();
  const j = await coba(() => sibuk($("#tutup-ya"), () => api("/api/peringatan/tutup", { metode: "POST", data: { aset_id: S.tutupAset, status, alasan } })));
  if (!j) return;
  $("#dialog-tutup").close();
  toast(`Peringatan ${j.nama} ditutup sebagai ${j.label}. Tercatat di ${T("buku_bukti")}.`, "sukses");
  setelahAksi();
}

// ==========================================================================
// v3: PETA ANCAMAN GLOBAL (Makro) ⇄ TOPOLOGI INTERNAL (Mikro)
// ==========================================================================
function gambarPeta(peta) {
  Peta.atur(peta);
  const m = $("#peta-markas"), [x, y] = Peta.proyeksi(peta.markas.lat, peta.markas.lon);
  m.setAttribute("transform", `translate(${x.toFixed(1)} ${y.toFixed(1)})`);
  m.dataset.status = peta.markas.status === "isolasi" ? "normal" : peta.markas.status;
  const hitung = (f) => peta.serangan.filter(f).length;
  const aktif = hitung((s) => s.jenis === "insiden" && s.status !== "diblokir");
  const ditahan = hitung((s) => s.status === "diblokir");
  const peringatan = hitung((s) => s.jenis === "cti" && s.status !== "abaikan");
  m.dataset.perisai = ditahan ? "1" : "0";
  $("#peta-hud").replaceChildren(
    el("span", { kelas: aktif ? "kritis" : "", teks: `${aktif} serangan aktif` }),
    el("span", { kelas: ditahan ? "diblokir" : "", teks: `${ditahan} ditahan perisai` }),
    el("span", { kelas: peringatan ? "waspada" : "", teks: `${peringatan} peringatan CTI` }),
    el("span", { kelas: peta.markas.gerbang, teks: `gerbang: ${peta.markas.gerbang}` }));

  const dampak = peta.dampak.slice(0, 6);
  $("#peta-dampak").replaceChildren(el("span", { teks: "Dampak di markas:" }),
    ...(dampak.length ? dampak.map((d) => el("span", { kelas: `chip-dampak ${d.status}`, title: d.catatan, teks: `${d.nama} · ${d.status.toUpperCase()}` }))
      : [el("span", { teks: "tidak ada aset terdampak" })]),
    dampak.length ? el("button", { type: "button", kelas: "tombol kecil", onclick: () => lihatDiTopologi(dampak.map((d) => d.id)) }, "Lihat di Topologi Internal →") : null);

  const luar = aktif + ditahan + peringatan;
  $("#topo-kaki").replaceChildren(...(luar ? [
    el("span", { teks: `↗ ${luar} trayektori ancaman dari luar sedang dipantau.` }),
    el("button", { type: "button", kelas: "tautan kecil", teks: "Lihat asal serangan di Peta Global", onclick: () => aturMode("makro") })] : []));
}

/** Dari peta global langsung ke denah: aset terdampak disorot berkedip. */
const SOROT = new Set();
function lihatDiTopologi(ids) {
  aturMode("mikro");
  ids.forEach((id) => { SOROT.add(id); TOPO.simpul[id]?.g.classList.add("sorot"); });
  setTimeout(() => { ids.forEach((id) => { SOROT.delete(id); TOPO.simpul[id]?.g.classList.remove("sorot"); }); }, 3200);
}

function aturMode(mode, simpan = true) {
  S.mode = mode;
  $("#tampilan-makro").hidden = mode !== "makro";
  $("#tampilan-mikro").hidden = mode !== "mikro";
  $$(".sakelar").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.mode === mode)));
  Peta.tampil(mode === "makro" && !$("#aplikasi").hidden);   // animasi peta hanya saat terlihat
  if (simpan) { try { localStorage.setItem("ns51-mode", mode); } catch { /* abaikan */ } }
  perbaruiNotifSakelar();
}

/** Titik merah di sakelar: "ada yang genting di tampilan sebelah". */
function perbaruiNotifSakelar() {
  const k = S.keadaan;
  if (!k) return;
  const mikroGenting = k.topologi.simpul.some((s) => s.status === "kritis");
  const makroAktif = k.peta.serangan.some((s) => s.status === "kritis" || s.status === "waspada");
  $("#mode-mikro .titik-notif").hidden = !(S.mode === "makro" && mikroGenting);
  $("#mode-makro .titik-notif").hidden = !(S.mode === "mikro" && makroAktif);
}

// ---------------------------------------------------------------- Alat: cek indikator
const POLA = {
  hash: /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$/i,
  domain: /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i,
  ipv4: /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/,
  ipv6: /^[0-9a-f:]+$/i,
};
function tebakJenis(v) {
  if (!v) return null;
  if (POLA.ipv4.test(v) || (v.includes(":") && POLA.ipv6.test(v))) return "Alamat IP";
  if (POLA.hash.test(v)) return { 32: "Hash MD5", 40: "Hash SHA-1", 64: "Hash SHA-256" }[v.length];
  if (POLA.domain.test(v)) return "Nama domain";
  return "";
}
function saatMengetik() {
  const v = $("#cari-nilai").value.trim(), j = tebakJenis(v);
  $("#jenis-tebakan").textContent = j === null ? " " : j ? `Terdeteksi sebagai: ${j}` : "Format belum dikenali (IP, domain, atau hash).";
  $("#cari-nilai").removeAttribute("aria-invalid");
}
async function cari(ev) {
  ev.preventDefault();
  const input = $("#cari-nilai"), v = input.value.trim();
  if (!tebakJenis(v)) { input.setAttribute("aria-invalid", "true"); toast("Masukkan IP, domain, atau hash yang valid.", "peringatan"); input.focus(); return; }
  const j = await coba(() => sibuk(ev.submitter, () => api("/api/indikator/cari", { metode: "POST", data: { nilai: v } })));
  if (!j) return;
  const ind = j.indikator, uji = ind && ind.tingkat === "uji";
  const kelas = !j.cocok ? "aman" : uji ? "uji" : "cocok";
  const judul = !j.cocok ? "Tidak ada di daftar ancaman" : uji ? "Cocok: berkas uji (tidak berbahaya)" : "Cocok dengan indikator ancaman!";
  $("#hasil-cari").replaceChildren(el("div", { kelas: `kotak-hasil ${kelas}` },
    el("h4", {}, ikon(j.cocok ? (uji ? "kuning" : "merah") : "hijau"), judul),
    j.cocok
      ? el("dl", {},
          el("dt", { teks: "ID" }), el("dd", { teks: ind.id }),
          el("dt", { teks: "Keterangan" }), el("dd", { teks: ind.label }),
          el("dt", { teks: "Tingkat" }), el("dd", { teks: ind.tingkat }),
          el("dt", { teks: "Jenis" }), el("dd", { teks: j.jenis }))
      : el("p", { kelas: "kecil", teks: "Tidak cocok dengan daftar contoh. Ini bukan jaminan aman: daftar hanya memuat ancaman yang sudah dikenal." }),
    j.cocok && !uji ? el("p", { kelas: "kecil", teks: "Saran: blokir di firewall, periksa log akses 7 hari terakhir, laporkan ke Tim Tanggap Insiden Siber." }) : null));
  S.riwayatCari.unshift({ nilai: v, kelas });
  S.riwayatCari = S.riwayatCari.slice(0, 8);
  gambarRiwayat();
}
function gambarRiwayat() {
  const ol = $("#riwayat-cari");
  if (!S.riwayatCari.length) { ol.replaceChildren(el("li", { kelas: "kosong", teks: "Belum ada pengecekan." })); return; }
  ol.replaceChildren(...S.riwayatCari.map((r) => el("li", {},
    el("button", { type: "button", kelas: "tautan mono", teks: r.nilai, title: "Cek lagi", onclick: () => { $("#cari-nilai").value = r.nilai; saatMengetik(); $("#form-cari").requestSubmit(); } }),
    lencana(r.kelas === "aman" ? "hijau" : r.kelas === "uji" ? "kuning" : "merah"))));
}

// ---------------------------------------------------------------- Alat: kepatuhan pencadangan
function gambarBackup() {
  $("#batas-jam").textContent = S.batasJam;
  $("#isi-backup").replaceChildren(...S.layanan.map((l) => {
    const telat = l.jam_sejak_backup > S.batasJam;
    return el("tr", {},
      el("th", { scope: "row" }, el("span", { kelas: "tebal", teks: l.nama }), el("br"), el("span", { kelas: "redup kecil", teks: l.sektor })),
      el("td", {}, el("span", { kelas: telat ? "tebal" : "", teks: umurBackup(l.jam_sejak_backup) }), telat ? el("br") : null, telat ? el("span", { kelas: "redup kecil", teks: `melewati batas ${S.batasJam} jam` }) : null),
      el("td", { teks: l.backup_teruji ? "Sudah diuji" : "Belum pernah" }),
      el("td", {}, lencana(l.status)),
      el("td", {}, el("div", { kelas: "aksi" },
        el("button", { type: "button", kelas: "tombol kecil", "data-ubah": "", "data-kunci": `bak-${l.id}-1`, teks: "Cadangkan + uji", onclick: (e) => catatBackup(l.id, true, e.currentTarget) }),
        el("button", { type: "button", kelas: "tombol halus kecil", "data-ubah": "", "data-kunci": `bak-${l.id}-0`, teks: "Cadangkan saja", onclick: (e) => catatBackup(l.id, false, e.currentTarget) }))));
  }));
}
async function catatBackup(id, uji_pulih, tombol) {
  const j = await coba(() => sibuk(tombol, () => api("/api/backup/catat", { metode: "POST", data: { layanan_id: id, uji_pulih } })));
  if (!j) return;
  toast(uji_pulih ? `Cadangan ${j.nama} dicatat dan sudah diuji pulih.` : `Cadangan ${j.nama} dicatat. Jangan lupa uji pemulihannya.`, uji_pulih ? "info" : "peringatan");
  setelahAksi();
}
async function majukanWaktu(ev) {
  const jam = Number(ev.currentTarget.dataset.jam);
  const j = await coba(() => sibuk(ev.currentTarget, () => api("/api/demo/majukan-waktu", { metode: "POST", data: { jam } })));
  if (j) { toast(`Waktu maju ${jam} jam.`); setelahAksi(); }
}

// ---------------------------------------------------------------- Alat: audit & LAPSIT
async function muatAudit(diam = false) {
  const j = await coba(() => api("/api/audit"));
  if (!j) return;
  const pertama = S.auditTerlihat.size === 0;
  S.audit = j.entri;
  $("#info-audit").textContent = `${j.entri.length} catatan terbaru${j.sementara ? " · log di memori (NS_AUDIT_KEY belum diatur)" : ""}`;
  const sel = $("#saring-aksi"), pilihan = sel.value;
  const aksiUnik = [...new Set(S.audit.map((e) => e.aksi))].sort();
  sel.replaceChildren(el("option", { value: "", teks: "Semua" }), ...aksiUnik.map((a) => el("option", { value: a, teks: a })));
  sel.value = aksiUnik.includes(pilihan) ? pilihan : "";
  gambarAudit(pertama && !diam);
}
const ringkasDetail = (d) => { const p = Object.entries(d || {}); return p.length ? p.map(([k, v]) => `${k}: ${v}`).join(" · ") : "–"; };
function gambarAudit(tanpaSorot) {
  const saring = $("#saring-aksi").value;
  const baris = S.audit.filter((e) => !saring || e.aksi === saring);
  $("#isi-audit").replaceChildren(...(baris.length ? baris.map((e) => el("tr", { kelas: !tanpaSorot && !S.auditTerlihat.has(e.hash) ? "baru" : null },
    el("td", { teks: e.urutan }),
    el("td", { title: e.waktu, teks: waktuLokal(e.waktu) }),
    el("td", { teks: e.aktor }),
    el("td", {}, el("span", { kelas: "label-aksi", teks: e.aksi })),
    el("td", { kelas: "detail-kv", teks: ringkasDetail(e.detail) }),
    el("td", { kelas: "sidik", title: e.hash, teks: `${e.hash.slice(0, 10)}…` })))
    : [el("tr", {}, el("td", { colspan: 6, kelas: "redup", teks: "Tidak ada catatan." }))]));
  S.audit.forEach((e) => S.auditTerlihat.add(e.hash));
}
async function verifikasi(ev) {
  const j = await coba(() => sibuk(ev.currentTarget, () => api("/api/audit/verifikasi")));
  if (!j) return;
  const sp = $("#hasil-verifikasi");
  sp.hidden = false;
  sp.className = `spanduk ${j.utuh ? "baik" : "buruk"}`;
  sp.replaceChildren(ikon(j.utuh ? "hijau" : "merah"), el("span", { teks: `${j.pesan} (${j.jumlah} catatan diperiksa)` }));
}
async function eksporLapsit(ev) {
  const r = await coba(() => sibuk(ev.currentTarget, () => api("/api/lapsit", { metode: "POST", mentah: true })));
  if (!r) return;
  const blob = await r.blob();
  const cocok = /filename="([^"]+)"/.exec(r.headers.get("Content-Disposition") || "");
  const a = el("a", { href: URL.createObjectURL(blob), download: cocok ? cocok[1] : "LAPSIT.pdf" });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  toast("LAPSIT PDF berhasil dibuat.");
  muatAudit();
}
async function resetDemo() {
  const ok = await konfirmasi("Reset demo?", "Semua layanan dan jaringan kembali ke kondisi awal. Log audit tetap disimpan sebagai bukti.", "Reset");
  if (!ok) return;
  if (await coba(() => api("/api/reset-demo", { metode: "POST" }))) { toast("Demo direset."); setelahAksi(); muatAudit(); }
}

// ---------------------------------------------------------------- Alat: drill kesiapan (app/drill.py)
// Kunci jawaban tidak pernah ada di browser sebelum pertanyaan dijawab; nilai dihitung server dari jejak tercatat.
const KELAS_BARIS_LOG = [[/^#|"event_type": "stats"/, "catatan"], [/Accepted |"function_raw": (5|6|15|16),/, "diterima"],
  [/Failed |"src_ip": "192\.0\.2\.183"/, "gagal"], [/sudo:/, "sudo"]];   // auth.log dan Suricata eve.json
const durasi = (detik) => `${Math.floor(detik / 60)}:${String(detik % 60).padStart(2, "0")}`;

async function muatDrill(diam = false) {
  const j = diam ? await api("/api/drill").catch(() => null) : await coba(() => api("/api/drill"));
  if (!j) return;
  const jejak = JSON.stringify([j, S.layanan.map((l) => Boolean(l.insiden))]);   // tombol Mulai ikut status insiden sasaran
  if (diam && jejak === S.drillJejak) return;          // tidak ada perubahan: jangan gambar ulang (posisi gulir log tetap)
  S.drill = j;
  S.drillJejak = jejak;
  denganFokus(gambarDrill);
  terapkanPeran();
}
function namaLayanan(id) { return S.layanan.find((l) => l.id === id)?.nama || id; }

function gambarDrill() {
  const { katalog, aktif, riwayat } = S.drill;
  const isi = [];
  if (aktif) isi.push(kartuDrillAktif(aktif));
  else {
    if (S.drillHasil) isi.push(kartuHasilDrill(S.drillHasil));
    for (const d of katalog) {
      const sibukLayanan = Boolean(S.layanan.find((l) => l.id === d.layanan_id)?.insiden);
      isi.push(el("div", { kelas: "kartu drill-katalog" },
        el("div", {}, el("p", { kelas: "label-kecil", teks: `Skenario drill · ${namaLayanan(d.layanan_id)} · log ${d.format}` }),
          el("h3", { teks: d.judul }), el("p", { kelas: "redup kecil", teks: d.ringkas }),
          sibukLayanan ? el("p", { kelas: "kecil drill-peringatan", teks: `${namaLayanan(d.layanan_id)} masih dalam insiden: pulihkan dulu dari Action Center, lalu mulai drill.` }) : null),
        el("button", { type: "button", kelas: "tombol utama", "data-ubah": "", "data-kunci": `drill-mulai-${d.kode}`,
          "data-terkunci": sibukLayanan ? true : null, teks: "Mulai drill", onclick: (e) => mulaiDrill(d, e.currentTarget) })));
    }
    if (!bolehUbah()) isi.push(el("p", { kelas: "redup kecil", teks: "Akun Pengamat hanya dapat melihat drill dan nilainya." }));
  }
  $("#drill-isi").replaceChildren(...isi);
  $("#drill-riwayat").replaceChildren(...(riwayat.length ? riwayat.map((h) => el("tr", {},
    el("td", {}, el("b", { teks: h.id }), el("br"), el("span", { kelas: "redup kecil", teks: h.judul })),
    el("td", { title: h.selesai, teks: waktuLokal(h.selesai) }),
    el("td", { teks: h.oleh }),
    el("td", {}, el("span", { kelas: `drill-huruf h-${h.huruf}`, teks: h.huruf }), ` ${h.nilai}/100`),
    el("td", { kelas: "kecil", teks: h.komponen.map((x) => `${x.label} ${x.nilai}/${x.maks}`).join(" · ") })))
    : [el("tr", {}, el("td", { colspan: 5, kelas: "redup", teks: "Belum ada drill yang dinilai." }))]));
  aturStopwatchDrill(aktif);
}

function kartuDrillAktif(a) {
  const baris = a.log.trimEnd().split("\n").map((b) => {
    const k = KELAS_BARIS_LOG.find(([pola]) => pola.test(b));
    return el("span", { kelas: `baris ${k ? k[1] : ""}` }, `${b}\n`);
  });
  const soal = a.pertanyaan.map((p, i) => {
    const dijawab = p.dijawab != null;
    const opsi = Object.entries(p.opsi).map(([kode, teks]) => el("button", {
      type: "button", kelas: `opsi-drill${dijawab && kode === p.kunci ? " benar" : ""}${dijawab && kode === p.dijawab && !p.benar ? " salah" : ""}`,
      "data-ubah": dijawab ? null : "", "data-kunci": `drill-${i}-${kode}`, disabled: dijawab, "aria-pressed": dijawab ? String(kode === p.dijawab) : null,
      onclick: (e) => jawabDrill(i, kode, e.currentTarget) }, el("b", { teks: `${kode.toUpperCase()}.` }), ` ${teks}`));
    return el("div", { kelas: "kartu drill-soal", "data-status": dijawab ? (p.benar ? "benar" : "salah") : "terbuka" },
      el("p", { kelas: "label-kecil", teks: `Fase ${i + 1} · ${p.fase}` }), el("p", { kelas: "drill-tanya", teks: p.teks }),
      el("div", { kelas: "drill-opsi" }, ...opsi),
      dijawab ? el("p", { kelas: "drill-penjelasan" }, el("b", { teks: p.benar ? "Benar. " : `Belum tepat. Jawaban: ${p.kunci.toUpperCase()}. ` }), p.penjelasan) : null);
  });
  const det = a.deteksi.map((d) => el("li", { kelas: d.muncul ? "ya" : "tidak" },
    ikon(d.muncul ? "hijau" : "merah"), `${d.nama}: ${d.muncul ? "muncul" : "TIDAK muncul"}`));
  return el("div", { kelas: "kartu drill-aktif" },
    el("div", { kelas: "drill-kepala" },
      el("div", {}, el("p", { kelas: "label-kecil", teks: `${a.id} · ${T("drill")} · berjalan` }), el("h3", { teks: a.judul }),
        el("p", { kelas: "redup kecil", teks: `Dimulai ${jamLokal(a.mulai)} oleh ${a.oleh} · sasaran ${namaLayanan(a.layanan_id)}` })),
      el("div", { kelas: "drill-stopwatch", "aria-label": "Waktu sejak drill dimulai" }, ikon("jam"), el("b", { id: "drill-stopwatch", teks: "0:00" }))),
    el("ol", { kelas: "drill-langkah" },
      el("li", { teks: "Baca log di bawah: apa yang terjadi, kapan, dan dari mana?" }),
      el("li", {}, "Tangani insiden ", el("b", { teks: namaLayanan(a.layanan_id) }), " di ", el("b", { teks: "Action Center" }),
        ". Tombol isolasi mengamankan bukti lebih dulu; stopwatch penahanan sudah berjalan."),
      el("li", { teks: "Jawab satu pertanyaan per fase. Jawaban tidak bisa diubah." }),
      el("li", { teks: "Tekan Selesai & hitung nilai." })),
    el("div", { kelas: "drill-dua" },
      el("div", {}, el("p", { kelas: "label-kecil", teks: `Log sintetis (${a.format})` }), el("pre", { kelas: "drill-log", tabindex: 0 }, ...baris),
        el("p", { kelas: "redup kecil", teks: `${a.impor.dikenali} dari ${a.impor.baris} baris dibaca aturan deteksi (${a.impor.format}); ${a.impor.diabaikan} baris lain (sudo, sesi, statistik sensor) diabaikan aturan, tetapi tetap bisa dibaca Operator.` })),
      el("div", {}, el("p", { kelas: "label-kecil", teks: "Kunci jawaban deteksi" }),
        el("p", { kelas: "redup kecil", teks: "Aturan yang seharusnya menangkap cerita ini. Bila ada yang tidak muncul, aturannya yang perlu diperiksa." }),
        el("ul", { kelas: "drill-deteksi" }, ...det))),
    el("div", { kelas: "drill-soal-daftar" }, ...soal),
    el("div", { kelas: "baris-aksi" },
      el("p", { kelas: "redup kecil", teks: `${a.terjawab} dari ${a.pertanyaan.length} pertanyaan terjawab. Nilai: ketepatan 40 + bukti sebelum putus 30 + kecepatan penahanan 30.` }),
      el("button", { type: "button", kelas: "tombol utama", "data-ubah": "", "data-kunci": "drill-selesai", teks: "Selesai & hitung nilai",
        onclick: (e) => selesaiDrill(a, e.currentTarget) })));
}

/** Batang kecil nilai. Lebar lewat CSSOM, bukan atribut style: CSP style-src 'self' menolak gaya inline. */
function batangNilai(rasio) {
  const b = el("div", { kelas: "drill-batang" });
  b.style.setProperty("--isi", `${Math.round(rasio * 100)}%`);
  return b;
}
function kartuHasilDrill(h) {
  return el("div", { kelas: "kartu drill-hasil" },
    el("div", { kelas: "drill-kepala" },
      el("div", {}, el("p", { kelas: "label-kecil", teks: `${h.id} · hasil · latihan` }), el("h3", { teks: h.judul }),
        el("p", { kelas: "redup kecil", teks: `Oleh ${h.oleh} · ${h.benar} dari ${h.jumlah_pertanyaan} jawaban benar` })),
      el("div", { kelas: "drill-skor" }, el("span", { kelas: `drill-huruf besar h-${h.huruf}`, teks: h.huruf }), el("b", { teks: `${h.nilai}` }), el("span", { kelas: "redup", teks: "/100" }))),
    el("div", { kelas: "gulir" }, el("table", { kelas: "tabel" },
      el("thead", {}, el("tr", {}, ...["Komponen", "Nilai", "Sumber angka", "Rincian"].map((t) => el("th", { scope: "col", teks: t })))),
      el("tbody", {}, ...h.komponen.map((x) => el("tr", {},
        el("td", { teks: x.label }),
        el("td", {}, batangNilai(x.nilai / x.maks), `${x.nilai}/${x.maks}`),
        el("td", { kelas: "kecil", teks: x.sumber }), el("td", { kelas: "kecil", teks: x.rincian })))))),
    el("p", { kelas: `kecil ${h.deteksi_lengkap ? "redup" : "drill-peringatan"}`, teks: `Kunci jawaban deteksi: ${h.catatan_deteksi}` }),
    el("div", { kelas: "baris-aksi" },
      el("p", { kelas: "redup kecil", teks: "Hasil ini tercatat di log audit berantai dan ikut tercetak di LAPSIT sebagai LATIHAN." }),
      el("button", { type: "button", kelas: "tombol halus", teks: "Buka Audit & LAPSIT", onclick: () => pilihTab("audit", true) })));
}

function aturStopwatchDrill(aktif) {
  clearInterval(S.timerDrill);
  if (!aktif) return;
  const mulai = Date.parse(aktif.mulai);
  const detak = () => { const s = $("#drill-stopwatch"); if (s) s.textContent = durasi(Math.max(0, Math.round((Date.now() - mulai) / 1000))); };
  detak();
  S.timerDrill = setInterval(detak, 1000);
}

async function mulaiDrill(d, tombol) {
  const ok = await konfirmasi(`Mulai drill: ${d.judul}?`, `Log sintetis diputar lewat aturan deteksi, lalu insiden latihan dimulai di ${namaLayanan(d.layanan_id)}. Tangani seperti insiden sungguhan; stopwatch penahanan langsung berjalan.`, "Mulai drill");
  if (!ok) return;
  const j = await coba(() => sibuk(tombol, () => api("/api/drill/mulai", { metode: "POST", data: { kode: d.kode } })));
  if (!j) return;
  S.drillHasil = null;
  toast(`${j.aktif.id} dimulai. Insiden latihan berjalan di ${namaLayanan(j.aktif.layanan_id)}.`, "peringatan");
  await muatDrill();
  setelahAksi();
}
async function jawabDrill(no, pilihan, tombol) {
  const j = await coba(() => sibuk(tombol, () => api("/api/drill/jawab", { metode: "POST", data: { no, pilihan } })));
  if (!j) return;
  toast(j.benar ? `Fase ${j.fase}: benar.` : `Fase ${j.fase}: belum tepat. Baca penjelasannya.`, j.benar ? "info" : "peringatan");
  muatDrill();
}
async function selesaiDrill(a, tombol) {
  const sisa = a.pertanyaan.length - a.terjawab;
  const ins = S.layanan.find((l) => l.id === a.layanan_id)?.insiden;
  const pesan = [sisa ? `${sisa} pertanyaan belum dijawab (dinilai 0).` : null,
    ins ? "Insiden latihan masih berjalan; nilai memakai jejak yang tercatat sampai saat ini." : null].filter(Boolean).join(" ");
  if (pesan && !(await konfirmasi("Akhiri drill sekarang?", pesan, "Hitung nilai"))) return;
  const j = await coba(() => sibuk(tombol, () => api("/api/drill/selesai", { metode: "POST" })));
  if (!j) return;
  S.drillHasil = j.hasil;
  toast(`Nilai kesiapan ${j.hasil.nilai}/100 (${j.hasil.huruf}).`);
  await muatDrill();
  setelahAksi();
}

// ---------------------------------------------------------------- tab alat operator
const TAB = ["indikator", "drill", "backup", "audit", "akun"];
const tabTersedia = () => TAB.filter((t) => !$(`#tab-${t}`).hidden);   // tab Akun tersembunyi untuk pengamat
function pilihTab(nama, fokus = false) {
  if ($(`#tab-${nama}`).hidden) nama = "indikator";
  for (const t of TAB) {
    const tombol = $(`#tab-${t}`), aktif = t === nama;
    tombol.setAttribute("aria-selected", String(aktif));
    tombol.tabIndex = aktif ? 0 : -1;
    $(`#panel-${t}`).hidden = !aktif;
    if (aktif && fokus) tombol.focus();
  }
  if (nama === "audit") muatAudit();
  if (nama === "drill") muatDrill();
  aturPemantauAkun(nama === "akun");
}
function navigasiTab(ev) {
  const ada = tabTersedia(), i = ada.indexOf(ev.currentTarget.id.replace("tab-", ""));
  const arah = { ArrowRight: 1, ArrowLeft: -1 }[ev.key];
  if (arah) { ev.preventDefault(); pilihTab(ada[(i + arah + ada.length) % ada.length], true); }
}

// ==========================================================================
// Fase 5 (audit #7): PENDAFTARAN AKUN & DASBOR AKUN OPERATOR
// ==========================================================================
const POLA_NAMA = /^[a-z][a-z0-9_]{2,19}$/, MIN_SANDI = 12;
const LABEL_ASAL = { bawaan: "Bawaan server", mandiri: "Daftar mandiri", kode_undangan: "Kode undangan", operator: "Dibuat Operator" };

function gantiForm(keDaftar) {
  $("#form-login").hidden = keDaftar;
  $("#form-daftar").hidden = !keDaftar;
  $("#ganti-form").textContent = keDaftar ? "Sudah punya akun? Masuk" : "Belum punya akun? Buat akun";
  $("#ganti-form").setAttribute("aria-expanded", String(keDaftar));
  (keDaftar ? $("#daftar-nama") : $("#login-nama")).focus();
}

/** Validasi di browser hanya demi kenyamanan; server tetap memeriksa ulang semuanya. */
async function daftarAkun(ev) {
  ev.preventDefault();
  const pesan = $("#pesan-daftar"), nama = $("#daftar-nama").value.trim();
  const sandi = $("#daftar-sandi").value, sandi2 = $("#daftar-sandi2").value;
  const peran = $("input[name=daftar-peran]:checked").value, kode = $("#daftar-kode").value;
  pesan.textContent = "";
  const salah = !POLA_NAMA.test(nama) ? ["#daftar-nama", "Nama akun 3–20 karakter: huruf kecil, angka, atau _, diawali huruf."]
    : sandi.length < MIN_SANDI ? ["#daftar-sandi", `Kata sandi minimal ${MIN_SANDI} karakter.`]
    : sandi.toLowerCase().includes(nama) ? ["#daftar-sandi", "Kata sandi tidak boleh memuat nama akun."]
    : sandi !== sandi2 ? ["#daftar-sandi2", "Ulangan kata sandi tidak sama."]
    : peran === "operator" && !kode ? ["#daftar-kode", "Akun Operator memerlukan kode undangan."] : null;
  $$("#form-daftar input").forEach((i) => i.removeAttribute("aria-invalid"));
  if (salah) { $(salah[0]).setAttribute("aria-invalid", "true"); $(salah[0]).focus(); pesan.textContent = salah[1]; return; }
  await sibuk($("#tombol-daftar"), async () => {
    try {
      const data = { nama, sandi, peran, ...(peran === "operator" ? { kode_operator: kode } : {}) };
      const j = await api("/api/akun/daftar", { metode: "POST", data });
      $("#form-daftar").reset(); $("#bidang-kode").hidden = true;
      gantiForm(false);
      $("#login-nama").value = j.nama;
      $("#login-sandi").focus();
      toast(`Akun ${j.nama} (${namaPeran(j.peran)}) dibuat. Silakan masuk.`, "sukses");
    } catch (e) { pesan.textContent = e.message; }
  });
}

let timerAkun = null;
function aturPemantauAkun(nyala) {
  clearInterval(timerAkun); timerAkun = null;
  if (!nyala || !bolehUbah()) return;
  muatAkun();
  timerAkun = setInterval(() => { if (!document.hidden && !$("#panel-akun").hidden) muatAkun(true); }, 5000);
}

async function muatAkun(diam = false) {
  let j;
  try { j = await api("/api/akun/ringkasan"); }
  catch (e) { if (!diam && e.status !== 401) toast(e.message, "galat"); return; }
  const p = j.hitung.pengamat, o = j.hitung.operator;
  $("#akun-pengamat-terdaftar").textContent = p.terdaftar;
  $("#akun-pengamat-aktif").textContent = p.aktif;
  $("#akun-pengamat-memantau").textContent = p.memantau;
  $("#akun-operator").textContent = `${o.terdaftar} · ${o.aktif}`;
  $("#info-akun").textContent = `Diperbarui ${new Date().toLocaleTimeString("id-ID")} · otomatis tiap 5 detik. `
    + `Pendaftaran Pengamat ${j.pendaftaran.pengamat_terbuka ? "terbuka" : "ditutup"}; `
    + `Operator mandiri ${j.pendaftaran.operator_dengan_kode ? "dengan kode undangan" : "ditutup (kode undangan belum diatur)"}.`;
  $("#isi-akun").replaceChildren(...j.akun.map((a) => {
    const [kelas, teks] = a.siaran ? ["memantau", "● Memantau"] : a.sesi ? ["login", "● Login"] : ["mati", "○ Tidak aktif"];
    return el("tr", {},
      el("td", {}, el("b", { teks: a.nama }), a.nama === S.akun ? el("span", { kelas: "redup kecil", teks: " (Anda)" }) : null),
      el("td", {}, el("span", { kelas: `chip-peran ${a.peran}`, teks: namaPeran(a.peran) })),
      el("td", { teks: LABEL_ASAL[a.asal] || a.asal }),
      el("td", {}, el("span", { kelas: `status-akun ${kelas}`, teks: teks })));
  }));
}

async function tambahAkun(ev) {
  ev.preventDefault();
  const pesan = $("#pesan-akun-baru"), nama = $("#baru-nama").value.trim(), sandi = $("#baru-sandi").value;
  pesan.textContent = "";
  if (!POLA_NAMA.test(nama)) { pesan.textContent = "Nama akun 3–20 karakter: huruf kecil, angka, atau _, diawali huruf."; return; }
  if (sandi.length < MIN_SANDI) { pesan.textContent = `Kata sandi minimal ${MIN_SANDI} karakter.`; return; }
  const j = await coba(() => sibuk($("#tombol-akun-baru"), () =>
    api("/api/akun", { metode: "POST", data: { nama, sandi, peran: $("#baru-peran").value } })));
  if (!j) return;
  $("#form-akun-baru").reset();
  toast(`Akun ${j.nama} (${namaPeran(j.peran)}) ditambahkan.`, "sukses");
  muatAkun();
}

// ---------------------------------------------------------------- login / keluar
async function masuk(ev) {
  ev.preventDefault();
  const nama = $("#login-nama").value.trim().toLowerCase(), sandiEl = $("#login-sandi"), pesan = $("#pesan-login");
  pesan.textContent = "";
  if (!POLA_NAMA.test(nama)) { pesan.textContent = "Isi nama akun yang terdaftar."; $("#login-nama").focus(); return; }
  if (!sandiEl.value) { sandiEl.setAttribute("aria-invalid", "true"); pesan.textContent = "Kata sandi wajib diisi."; sandiEl.focus(); return; }
  sandiEl.removeAttribute("aria-invalid");
  await sibuk($("#tombol-masuk"), async () => {
    try {
      const j = await api("/api/login", { metode: "POST", data: { nama, sandi: sandiEl.value } });
      S.token = j.token; S.akun = j.nama; S.peran = j.peran;
      if (j.wajib_ganti) { mintaGantiSandi(sandiEl.value); sandiEl.value = ""; return; }
      sandiEl.value = "";
      bukaAplikasi();
    } catch (e) {
      pesan.textContent = e.status === 401 ? "Nama atau kata sandi salah." : e.message;
      sandiEl.select();
    }
  });
}
// Pemasangan produksi: akun bawaan wajib mengganti sandi awal. Sandi awal dipegang sementara di variabel
// lokal (tidak disimpan di mana pun) lalu dihapus begitu sandi berhasil diganti atau pengguna keluar.
let sandiAwal = "";
function mintaGantiSandi(sandi) {
  sandiAwal = sandi;
  $("#form-login").hidden = true;
  $("#form-ganti-sandi").hidden = false;
  $("#baris-ganti-form").hidden = $("#catatan-sandi-demo").hidden = true;
  $("#ganti-nama").textContent = S.akun;
  $("#pesan-ganti").textContent = "";
  $("#ganti-baru").focus();
}
function tutupGantiSandi() {
  sandiAwal = "";
  $("#ganti-baru").value = $("#ganti-ulang").value = "";
  $("#form-ganti-sandi").hidden = true;
  $("#form-login").hidden = false;
  $("#baris-ganti-form").hidden = $("#catatan-sandi-demo").hidden = false;
}
async function simpanSandiBaru(ev) {
  ev.preventDefault();
  const baru = $("#ganti-baru").value, pesan = $("#pesan-ganti");
  pesan.textContent = "";
  if (baru.length < 12) { pesan.textContent = "Sandi baru minimal 12 karakter."; $("#ganti-baru").focus(); return; }
  if (baru !== $("#ganti-ulang").value) { pesan.textContent = "Kedua isian sandi baru tidak sama."; $("#ganti-ulang").focus(); return; }
  await sibuk($("#tombol-ganti-sandi"), async () => {
    try {
      await api("/api/akun/ganti-sandi", { metode: "POST", data: { sandi_lama: sandiAwal, sandi_baru: baru } });
      tutupGantiSandi();
      bukaAplikasi();
      toast("Sandi baru tersimpan. Sesi lain akun ini sudah dicabut.", "sukses");
    } catch (e) {
      pesan.textContent = e.message;
    }
  });
}
async function batalGantiSandi() {
  tutupGantiSandi();
  await coba(() => api("/api/logout", { metode: "POST" }));
  S.token = S.akun = S.peran = null;
  $("#pesan-login").textContent = "Sandi awal belum diganti; dasbor belum bisa dipakai.";
}
function bukaAplikasi() {
  $("#bagian-login").hidden = true;
  $("#aplikasi").hidden = false;
  $("#info-sesi").hidden = false;
  $("#nama-sesi").textContent = S.akun;
  $("#peran-sesi").textContent = `· ${namaPeran(S.peran)}`;
  $("#avatar-sesi").textContent = S.akun.slice(0, 1);
  S.insidenSebelumnya = null; S.seqTampil = 0; S.versi = -1; S.irTerlihat = null; S.idDasar = null; S.menungguPotret = false;
  $("#log-jaringan").replaceChildren();
  pilihTab("indikator");
  S.kunciTicker = ""; kunciPrediksi = "";
  aturMode(S.mode, false);
  terapkanPeran();
  bukaSiaran();                       // ← mulai berlangganan siaran dari server
  clearInterval(S.timerJam);
  S.timerJam = setInterval(() => $$(".relatif").forEach((s) => { s.textContent = waktuRelatif(s.dataset.iso); }), 30000);
  toast(`Selamat datang, ${S.akun}.`);
}
function keluarLokal(pesan) {
  tutupSiaran();
  aturPemantauAkun(false);
  Peta.tampil(false);
  S.token = S.akun = S.peran = null;
  clearInterval(S.timerJam);
  clearInterval(S.timerDrill);
  S.drill = S.drillHasil = null;
  tutupLaci();
  aturKoneksi("mati");
  $("#pil-postur").hidden = true;
  $("#aplikasi").hidden = true;
  $("#info-sesi").hidden = true;
  $("#bagian-login").hidden = false;
  if (pesan) $("#pesan-login").textContent = pesan;
  $("#login-sandi").focus();
}
async function keluar() {
  await coba(() => api("/api/logout", { metode: "POST" }));
  keluarLokal("Anda telah keluar.");
}

// ---------------------------------------------------------------- mode edukasi
function aturEdu(nyala) {
  document.body.classList.toggle("edu-on", nyala);
  $("#tombol-edu").setAttribute("aria-pressed", String(nyala));
  try { localStorage.setItem("ns51-edu", nyala ? "1" : "0"); } catch { /* penyimpanan tidak tersedia */ }
}

// ---------------------------------------------------------------- sambungkan semua
document.addEventListener("DOMContentLoaded", () => {
  muatIstilah();                                         // Fase 1: label dari app/istilah.py
  let edu = false;                                       // v5.1: default minimalis, edukasi bisa dinyalakan
  try { edu = localStorage.getItem("ns51-edu") === "1"; } catch { /* abaikan */ }
  aturEdu(edu);
  $("#tombol-edu").addEventListener("click", () => aturEdu(!document.body.classList.contains("edu-on")));
  $("#tombol-log").addEventListener("click", (e) => {             // v5.1: log ringkas (2 baris) ⇄ semua
    const ringkas = $("#log-jaringan").classList.toggle("ringkas");
    e.currentTarget.setAttribute("aria-expanded", String(!ringkas));
    e.currentTarget.textContent = ringkas ? "Semua" : "Ringkas";
  });

  Radar.init($("#radar"), $("#radar-kotak"), $("#radar-tip"));
  $("#tombol-jeda").addEventListener("click", (e) => {
    const jalan = Radar.alih();
    e.currentTarget.setAttribute("aria-pressed", String(!jalan));
    e.currentTarget.textContent = jalan ? "Jeda radar" : "Lanjutkan radar";
  });

  Peta.init($("#peta-kanvas"), $("#peta-kotak"));
  try { const m = localStorage.getItem("ns51-mode"); if (m === "makro" || m === "mikro") S.mode = m; } catch { /* abaikan */ }
  $$(".sakelar").forEach((b) => b.addEventListener("click", () => aturMode(b.dataset.mode)));
  $("#tombol-siarkan").addEventListener("click", (e) => siarkanBerita(e.currentTarget));
  // Fase 6: latihan IT/OT yang bisa diulang — siarkan kabar ancaman Modbus (aset OT genset)
  $("#tombol-siarkan-ot").addEventListener("click", (e) => siarkanBerita(e.currentTarget, "CTI-109"));
  $("#tombol-latihan-ai").addEventListener("click", (e) => latihanAI(e.currentTarget, "genset"));
  $$("[data-deteksi]").forEach((b) => b.addEventListener("click", (e) => latihanDeteksi(e.currentTarget, e.currentTarget.dataset.deteksi)));
  $("#tombol-impor-log").addEventListener("click", () => $("#berkas-impor-log").click());
  $("#berkas-impor-log").addEventListener("change", (e) => { imporLog(e.target.files[0]); e.target.value = ""; });
  $("#form-tutup").addEventListener("submit", kirimTutup);
  $("#tutup-alasan").addEventListener("input", hitungAlasanTutup);

  $("#form-login").addEventListener("submit", masuk);
  $("#form-ganti-sandi").addEventListener("submit", simpanSandiBaru);
  $("#tombol-batal-ganti").addEventListener("click", batalGantiSandi);
  $("#form-daftar").addEventListener("submit", daftarAkun);
  $("#ganti-form").addEventListener("click", () => gantiForm($("#form-daftar").hidden));
  $$("input[name=daftar-peran]").forEach((r) => r.addEventListener("change", () => {
    const operator = $("input[name=daftar-peran]:checked").value === "operator";
    $("#bidang-kode").hidden = !operator;
    if (operator) $("#daftar-kode").focus();
  }));
  $("#form-akun-baru").addEventListener("submit", tambahAkun);
  $("#intip-sandi").addEventListener("click", (e) => {
    const i = $("#login-sandi"), tampil = i.type === "password";
    i.type = tampil ? "text" : "password";
    e.currentTarget.textContent = tampil ? "Sembunyikan" : "Tampilkan";
    e.currentTarget.setAttribute("aria-pressed", String(tampil));
  });
  $("#tombol-keluar").addEventListener("click", keluar);

  $$(".opsi-skenario").forEach((b) => b.addEventListener("click", (e) => picuLatihan(b.dataset.skenario, e.currentTarget)));

  for (const t of TAB) {
    $(`#tab-${t}`).addEventListener("click", () => pilihTab(t));
    $(`#tab-${t}`).addEventListener("keydown", navigasiTab);
  }
  $("#form-cari").addEventListener("submit", cari);
  $("#cari-nilai").addEventListener("input", saatMengetik);
  $$(".isi-contoh").forEach((b) => b.addEventListener("click", () => { $("#cari-nilai").value = b.textContent; saatMengetik(); $("#form-cari").requestSubmit(); }));
  gambarRiwayat();
  $$(".majukan").forEach((b) => b.addEventListener("click", majukanWaktu));
  $("#tombol-verifikasi").addEventListener("click", verifikasi);
  $("#tombol-lapsit").addEventListener("click", eksporLapsit);
  $("#tombol-reset").addEventListener("click", resetDemo);
  $("#tombol-ke-drill").addEventListener("click", () => { pilihTab("drill", true); $("#panel-drill").scrollIntoView({ behavior: "smooth", block: "start" }); });
  // drill berjalan: segarkan tiap 5 dtk selama tab terlihat (Pengamat ikut memantau jawaban dan nilai)
  setInterval(() => { if (S.token && !$("#panel-drill").hidden && document.visibilityState === "visible") muatDrill(true); }, 5000);
  $("#saring-aksi").addEventListener("change", () => gambarAudit(true));

  $("#laci-tutup").addEventListener("click", tutupLaci);
  $("#laci-latar").addEventListener("click", tutupLaci);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && S.lacikLayananId) tutupLaci(); });

  // Kembali ke tab setelah lama tersembunyi: pastikan siaran masih hidup
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && S.token && S.koneksi !== "langsung" && !S.siaran.ctrl) bukaSiaran();
  });

  $("#login-sandi").focus();
});
