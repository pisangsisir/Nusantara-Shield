# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
telemetri.py — "Dapur" pemantauan jaringan sintetis (v4: + CTI, SOAR, Rantai Komando).

Analogi restoran (v2):
- Dapur (modul ini) memasak SEMUA angka: status perangkat, beban lalu lintas,
  titik radar, catatan kejadian. Browser hanya menyajikan.
- "versi" = nomor pesanan. Naik setiap kali resep berubah; pelayan siaran
  mengantar hidangan lengkap begitu nomornya berubah.

Tambahan v3, analogi "alarm rumah & radio satpam":
- GeneratorOSINT = RADIO SATPAM. Berkala menyiarkan kabar ancaman sintetis
  ("ada maling mencoba pintu samping di kompleks sebelah").
- Korelasi = SATPAM YANG MENCOCOKKAN kabar itu dengan denah rumah kita
  (inventaris aset). Kabar soal "pintu samping" (port 445) hanya relevan bila
  rumah kita PUNYA pintu samping. Bila cocok, lampu teras dinyalakan kuning
  (status "waspada") SEBELUM maling benar-benar datang.
- SOAR = TOMBOL PANIK PINTAR. Satu tekan, beberapa pintu terkunci otomatis
  (kabel diputus, IP diblokir), dan beban jaringan langsung turun.

Doktrin v5.1, analogi "sprinkler & panggilan otomatis ke pemadam":
- PRE-AUTHORIZED CONTAINMENT: operator tim insiden boleh langsung mengisolasi aset yang
  terkonfirmasi diserang; izinnya sudah disetujui manajemen di playbook jauh hari.
- AUTOMATED IR BLAST: laporan otomatis ke manajemen. Manajemen DIBERI TAHU, tidak dimintai izin.
- QUICK CALL: telepon hanya ke PIC teknis cabang agar server yang diisolasi tidak di-restart.

Fase 1 (perbaikan pasca-audit):
- F-04  ISOLASI dan PEMULIHAN dipisah. Tombol isolasi hanya menjalankan tindakan bertanda
        jenis="pemutus". Pemulihan punya pintu sendiri yang terkunci sampai aset terisolasi
        (laporan sudah terkirim) DAN langkah playbook sebelum langkah pemulihan sudah dicentang.
- F-02  Laporan hanya dibuat SETELAH seluruh tindakan pemutus benar-benar selesai, dan isinya
        memuat jejak nyata tiap tindakan (siapa/apa yang menjalankan, detik ke berapa).
- F-03  Nomor laporan dari penomoran.PENCACAH: tidak ikut reset, opsional persisten, + UUID.
- F-10  Semua label manusiawi dibaca dari istilah.ISTILAH.

Fase 4 (rantai bukti forensik — analogi olah TKP: foto & kantongi barang bukti DULU, baru pasang
garis polisi; TKP baru boleh dibersihkan setelah segel bukti dicocokkan):
- Setiap playbook diawali langkah AMANKAN BUKTI (jenis="bukti"): salinan simulasi + SHA-256 +
  berita acara di buku rantai bukti (app/bukti.py, berantai HMAC).
- Server MENOLAK (409) setiap pemutusan — tombol, aksi tunggal, centang manual, maupun antrean —
  selama bukti belum diamankan. Satu-satunya pengecualian: ISOLASI DARURAT dengan alasan tertulis
  yang langsung masuk buku rantai bukti, log audit HMAC, dan laporan ke manajemen.
- Pemulihan (tombol, centang manual, tutup insiden) WAJIB lolos pencocokan ulang SHA-256 seluruh
  barang bukti dan keutuhan rantai buku; hasil pencocokan juga dicatat di buku.

Aturan pakai: semua metode Menara dipanggil SAMBIL memegang kunci state
(_kunci_state di main.py), supaya dapur tidak dimasak dua koki sekaligus.
Fase 2: maju()/potret()/detak() kini dipanggil oleh SATU tugas latar (dapur() di main.py) sekali per
detik, bukan oleh setiap layar. Jam simulasi tetap berjalan walau tidak ada layar yang terbuka.

Semua data sintetis. IP memakai blok dokumentasi RFC 5737.
"""

from __future__ import annotations

import hashlib
import math
import os
import random
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Callable

from .data_contoh import (BATAS_JAM_BACKUP, BERITA_ANCAMAN, INDEKS_BERITA, KEBIJAKAN, KEPARAHAN_IR, LANGKAH_IR,
                          MANAJEMEN, PLAYBOOK, PLAYBOOK_RINGKAS, PROFIL_LAYANAN)
from .istilah import ISTILAH, nama_manajemen, pesan_jangan_restart
from .bukti import (BUKTI_DIAMANKAN, BUKTI_DIVERIFIKASI, BUKTI_GAGAL, ISOLASI_DARURAT, PERINGATAN_DITUTUP, RANTAI,
                    VERIFIKASI_GAGAL, RantaiBukti)
from .penomoran import PENCACAH, PencacahIR
from .ai_anomali import DETEKTOR, POLA, POLA_SKENARIO, ciri_normal, ciri_pola
from .deteksi import (NAMA_FUNGSI_MODBUS, ASET_LATIHAN_OT, ATURAN as ATURAN_DETEKSI, AWALAN as AWALAN_DET, JENIS_LATIHAN, MesinDeteksi,
                      rangkaian_latihan)
from .mitre import ringkas as ringkas_mitre, teknik as teknik_mitre
from .impor_log import baca as baca_log

# Label batasan (kejujuran) per jenis peringatan: dari mana datanya, dan apa yang masih simulasi.
SUMBER_DATA = {
    "deteksi": "Sumber: peristiwa latihan sintetis · aturan deteksi berjalan nyata",
    "impor": "Sumber: log impor «{berkas}» dari Operator · aturan deteksi berjalan nyata",
    "ai": "Sumber: ciri lalu lintas sintetis · model AI berjalan nyata di server ini",
    "insiden": "Sumber: skenario latihan · perintah ke perangkat jaringan masih simulasi",
}

# --------------------------------------------------------------------------
# 1. TOPOLOGI JARINGAN CONTOH (data, bukan tata letak)
# --------------------------------------------------------------------------
# r       = jarak di radar (0 = pusat, 1 = tepi): < .5 internal, .5–.75 DMZ, > .75 luar gerbang.
# paparan = seberapa mudah aset dijangkau penyerang (0..1). Aset DMZ yang menghadap
#           internet paling terpapar; aset di dalam jaringan lebih terlindung.
SIMPUL: list[dict] = [
    {"id": "internet", "nama": "Internet",         "ip": "—",          "port": None, "zona": "luar"},
    {"id": "fw",       "nama": "Gerbang/firewall", "ip": "192.0.2.1",  "port": None, "zona": "batas"},
    {"id": "core",     "nama": "Sakelar inti",     "ip": "192.0.2.2",  "port": None, "zona": "internal"},
    {"id": "portal",   "nama": "Portal web",       "ip": "192.0.2.10", "port": 443,  "zona": "dmz", "r": .60, "paparan": 1.0},
    {"id": "api",      "nama": "API layanan",      "ip": "192.0.2.48", "port": 8080, "zona": "dmz", "r": .68, "paparan": 0.9},
    {"id": "dns",      "nama": "DNS internal",     "ip": "192.0.2.60", "port": 53,   "zona": "internal", "r": .20, "paparan": 0.5},
    {"id": "db",       "nama": "Basis data",       "ip": "192.0.2.35", "port": 5432, "zona": "internal", "r": .28, "paparan": 0.45},
    {"id": "smb",      "nama": "Berbagi berkas",   "ip": "192.0.2.77", "port": 445,  "zona": "internal", "r": .36, "paparan": 0.7},
    {"id": "ssh",      "nama": "Akses admin SSH",  "ip": "192.0.2.21", "port": 22,   "zona": "internal", "r": .42, "paparan": 0.6},
    {"id": "rdp",      "nama": "Remote desktop",   "ip": "192.0.2.90", "port": 3389, "zona": "internal", "r": .46, "paparan": 0.95,
     "status": "waspada", "catatan": "Port RDP terbuka ke jaringan — sebaiknya ditutup"},
    {"id": "backup",   "nama": "Server cadangan",    "ip": "192.0.2.99", "port": 873,  "zona": "internal", "r": .13, "paparan": 0.6},
    # Fase 6 (IT/OT): aset teknologi operasional. Pengendali genset catu daya markas berbicara
    # protokol kendali industri Modbus/TCP (port 502). Kabar ancaman Modbus di Radio CTI kini
    # dikorelasikan ke aset ini (0,80 × 0,75 × 1,1 ≈ 66% → WASPADA), sama seperti aset IT.
    {"id": "genset",   "nama": "Pengendali genset", "ip": "192.0.2.120", "port": 502, "zona": "internal", "r": .40, "paparan": 0.75},
]
INDEKS_SIMPUL = {s["id"]: s for s in SIMPUL}
# v5: titik topologi → layanan pemilik (agar klik pada peta topologi membuka Secure Command Drawer).
# Aset bersama (internet, gerbang, sakelar inti) tidak punya pemilik tetap: saat insiden,
# pemiliknya adalah layanan yang insidennya membuat titik itu berubah status.
PEMILIK_SIMPUL = {"portal": "perizinan", "api": "imigrasi", "dns": "imigrasi", "db": "pajak",
                  "smb": "kesehatan", "rdp": "listrik", "ssh": "logistik", "backup": "pajak",
                  "genset": "listrik"}   # Fase 6: aset OT milik layanan Genset & Catu Daya RS Kesdam
PORT_INVENTARIS = {s["port"] for s in SIMPUL if s["port"]}
ASET_BERPORT = [s["id"] for s in SIMPUL if s["port"]]

KABEL: list[tuple[str, str, str]] = [  # (dari, ke, jenis)
    ("ancaman", "internet", "data"), ("internet", "fw", "data"),
    ("fw", "portal", "data"), ("fw", "api", "data"),
    ("portal", "core", "data"), ("api", "core", "data"),
    ("core", "dns", "data"), ("core", "db", "data"), ("core", "smb", "data"),
    ("core", "ssh", "data"), ("core", "rdp", "data"), ("core", "backup", "cadangan"),
    ("core", "genset", "data"),    # Fase 6: jalur IT → zona kendali (OT)
]

# "isolasi" = sengaja diputus petugas: lebih baik dari waspada, lebih buruk dari normal.
PERINGKAT = {"normal": 0, "isolasi": 1, "waspada": 2, "kritis": 3}

BEBAN_DASAR = {"target": 34.0, "goyang": 5.0, "lonjakan": 0.0}
AMBANG = {"waspada": 60, "kritis": 85}
PUTARAN_MS = {"aman": 4000, "waspada": 3200, "kritis": 2200}
PANJANG_RIWAYAT = 48
MENIT_LINIMASA = 60          # linimasa beban: 60 keranjang × 1 menit
BENIH_LINIMASA = 5100        # benih tetap: 60 menit data latihan sebelum posko dibuka, sama di setiap layar
JEDA_INFO_RUTIN = 12

# -- parameter Threat Intelligence ---------------------------------------------
JEDA_CTI = int(os.getenv("NS_CTI_JEDA", "30"))   # detik antar-berita otomatis
CTI_PERTAMA = 6                                   # berita pertama muncul cepat agar demo hidup
MAKS_CTI_AKTIF = 3
AMBANG_PROAKTIF = 0.5      # peluang ≥ 50% → aset dinaikkan ke "waspada" sebelum diserang
BONUS_SEKTOR = 1.1         # berita menyasar sektor yang KITA layani → sedikit lebih relevan
FAKTOR_PERKETAT = 0.3      # setelah pengerasan (SOAR), paparan tinggal 30%
SUMBER_AI = "AI-ANOMALI"   # penanda sumber peluang dari mesin deteksi anomali lokal (app/ai_anomali.py)
DURASI_LATIHAN_AI = 300    # detik: lamanya pola lalu lintas latihan disuntikkan ke satu aset
MAKS_PERINGATAN = 6        # daftar peringatan terbaru di dasbor

# -- Peta Ancaman Global (makro) ---------------------------------------------
# Titik koordinat KASAR per wilayah (lintang, bujur). Asal serangan di demo ini FIKTIF:
# dipakai untuk menggambar arah datangnya ancaman, bukan untuk menuduh pihak mana pun.
WILAYAH: dict[str, dict] = {
    "eropa_timur":     {"nama": "Eropa Timur",     "lat": 50.0,  "lon": 30.0},
    "eropa_barat":     {"nama": "Eropa Barat",     "lat": 48.0,  "lon": 5.0},
    "asia_timur":      {"nama": "Asia Timur",      "lat": 35.0,  "lon": 115.0},
    "asia_selatan":    {"nama": "Asia Selatan",    "lat": 22.0,  "lon": 78.0},
    "asia_tenggara":   {"nama": "Asia Tenggara",   "lat": 15.0,  "lon": 101.0},
    "timur_tengah":    {"nama": "Timur Tengah",    "lat": 28.0,  "lon": 47.0},
    "amerika_utara":   {"nama": "Amerika Utara",   "lat": 40.0,  "lon": -98.0},
    "amerika_selatan": {"nama": "Amerika Selatan", "lat": -15.0, "lon": -55.0},
    "afrika_barat":    {"nama": "Afrika Barat",    "lat": 9.0,   "lon": 3.0},
}
MARKAS = {"nama": "Markas latihan (sintetis) · Nusantara", "lat": -6.2, "lon": 106.8}

# --------------------------------------------------------------------------
# 2. DAMPAK SKENARIO KE JARINGAN + EFEK TIAP LANGKAH PLAYBOOK
# --------------------------------------------------------------------------
DAMPAK: dict[str, dict] = {
    "ransomware": {
        "perangkat": {"fw": ("waspada", "Koneksi keluar ke server kendali"),
                      "core": ("waspada", "Lalu lintas berbagi berkas tak wajar"),
                      "ssh": ("waspada", "Login admin dari 203.0.113.45"),
                      "smb": ("kritis", "Enkripsi massal berkas"),
                      "backup": ("kritis", "Direktori cadangan dinonaktifkan")},
        "ancaman": [{"ip": "203.0.113.45", "port": 443, "nama": "Server kendali (C2)", "ioc": "IOC-001",
                     "asal": "eropa_timur"}],
        "kerumunan": 0, "target": 60.0, "goyang": 7.0, "lonjakan": 0.2,
        "langkah": {
            1: {"ket": "Berbagi berkas & alamat penyerang diputus dari jaringan",
                "perangkat": {"smb": ("isolasi", "Diisolasi dari jaringan"),
                              "fw": ("waspada", "Koneksi ke server kendali diblokir")},
                "ancaman": "isolasi", "target": 38.0, "lonjakan": 0.0},
            2: {"ket": "Server cadangan dilepas (luring) agar tidak ikut terenkripsi",
                "perangkat": {"backup": ("isolasi", "Dilindungi: disimpan luring")}},
            5: {"ket": "Layanan dihidupkan dari cadangan teruji",
                "perangkat": {"core": ("normal", "Normal"), "ssh": ("normal", "Sandi admin diganti")}},
        },
    },
    "ddos": {
        "perangkat": {"internet": ("kritis", "Sumber trafik banjir"),
                      "fw": ("kritis", "Antrean koneksi penuh"),
                      "portal": ("kritis", "Kelebihan beban"),
                      "api": ("waspada", "Respons melambat")},
        "ancaman": [{"ip": "198.51.100.23", "port": 80, "nama": "Sumber trafik dominan", "ioc": "IOC-002",
                     "asal": "amerika_utara"}],
        # botnet tersebar: sumber banjir datang dari banyak wilayah sekaligus
        "asal_kerumunan": ["eropa_timur", "asia_timur", "amerika_selatan", "afrika_barat",
                           "asia_selatan", "eropa_barat"],
        "kerumunan": 16, "target": 94.0, "goyang": 4.0, "lonjakan": 0.0,
        "langkah": {
            1: {"ket": "Sumber banjir diblokir & trafik disaring: beban turun drastis",
                "perangkat": {"internet": ("waspada", "Trafik disaring penyedia"),
                              "fw": ("waspada", "Penyaringan aktif")},
                "ancaman": "isolasi", "kerumunan": 4, "target": 50.0},
            2: {"ket": "Fitur non-inti ditunda: portal kembali bernapas",
                "perangkat": {"portal": ("waspada", "Mode hemat: fitur inti saja"),
                              "api": ("normal", "Normal")},
                "target": 42.0},
            5: {"ket": "Kapasitas normal dipulihkan",
                "perangkat": {"internet": ("normal", "Normal"), "fw": ("normal", "Normal"),
                              "portal": ("normal", "Normal")},
                "kerumunan": 0, "target": 36.0},
        },
    },
    # Fase 6 (IT/OT): pemutusan OT mengikuti NIST SP 800-82 — yang diputus JALUR kantor → zona kendali,
    # bukan pengendalinya; genset tetap menyala dengan kendali lokal.
    "sabotase_ot": {
        "perangkat": {"rdp": ("waspada", "Login jarak jauh dari 203.0.113.45 ke workstation teknisi"),
                      "core": ("waspada", "Lalu lintas Modbus tak biasa dari jaringan kantor"),
                      "genset": ("kritis", "Perintah tulis Modbus asing")},
        "ancaman": [{"ip": "203.0.113.45", "port": 502, "nama": "Pengirim perintah Modbus", "ioc": "IOC-001",
                     "asal": "timur_tengah"}],
        "kerumunan": 0, "target": 46.0, "goyang": 5.0, "lonjakan": 0.0,
        "langkah": {
            1: {"ket": "Webhook (simulasi) ke sakelar terkelola zona kendali: uplink kantor diputus; "
                       "genset tetap menyala dengan kendali lokal",
                "perangkat": {"genset": ("isolasi", "Terputus dari jaringan kantor · kendali lokal"),
                              "core": ("normal", "Normal")},
                "ancaman": "isolasi", "target": 38.0},
            2: {"ket": "Akses jarak jauh workstation teknisi dicabut; alamat penyerang diblokir",
                "perangkat": {"rdp": ("isolasi", "Akses jarak jauh dicabut")}},
            5: {"ket": "Jalur kendali disambung kembali setelah konfigurasi pengendali dicocokkan",
                "perangkat": {"genset": ("normal", "Normal")}},
        },
    },
    "backup_dimatikan": {
        "perangkat": {"ssh": ("waspada", "Login admin dari 203.0.113.45"),
                      "backup": ("kritis", "Direktori cadangan dilepas")},
        "ancaman": [{"ip": "203.0.113.45", "port": 22, "nama": "Alamat login mencurigakan", "ioc": "IOC-001",
                     "asal": "timur_tengah"}],
        "kerumunan": 0, "target": 40.0, "goyang": 5.0, "lonjakan": 0.0,
        "langkah": {
            2: {"ket": "Pencadangan menyala lagi dan salinan darurat dibuat",
                "perangkat": {"backup": ("normal", "Pencadangan berjalan kembali")}},
            3: {"ket": "Akun mencurigakan dicabut; alamat penyerang diblokir",
                "perangkat": {"ssh": ("isolasi", "Akses dicabut sementara")},
                "ancaman": "isolasi"},
        },
    },
}

# --------------------------------------------------------------------------
# 3. KATALOG SOAR — langkah playbook yang BISA diotomatisasi
# --------------------------------------------------------------------------
# Langkah lain (lapor, jangan bayar tebusan, informasikan publik, evaluasi)
# sengaja tetap MANUSIA: keputusan dan komunikasi tidak diserahkan ke mesin.
# F-04: setiap tindakan punya JENIS:
#   "bukti"     = Fase 4: mengamankan barang bukti (SHA-256 + buku rantai bukti). SELALU langkah pertama.
#   "pemutus"   = memutus jaringan / memblokir. HANYA ini yang dijalankan tombol EKSEKUSI ISOLASI,
#                 dan hanya SETELAH bukti diamankan (kecuali ISOLASI DARURAT beralasan).
#   "pemulihan" = menghidupkan layanan kembali. Pintunya terpisah dan terkunci (syarat_pemulihan).
#   "pendukung" = tindakan lain; dijalankan satu per satu atau lewat centang playbook.
def _aksi_bukti(ket: str) -> dict:
    return {"id": "amankan_bukti", "label": ISTILAH["langkah_bukti"], "ikon": "periksa", "langkah": 0,
            "jenis": "bukti", "ket": ket}


SOAR: dict[str, list[dict]] = {
    "ransomware": [
        _aksi_bukti("Salin memori & log server terdampak, hitung SHA-256, catat berita acara"),
        {"id": "isolasi_otomatis", "label": "Isolasi otomatis", "ikon": "potong", "langkah": 1, "jenis": "pemutus",
         "ket": "Putus server terdampak & blokir alamat C2 di gerbang"},
        {"id": "amankan_backup", "label": "Amankan cadangan", "ikon": "cadangan", "langkah": 2, "jenis": "pemutus",
         "ket": "Lepas server cadangan dari jaringan (luring)"},
        {"id": "pulihkan_sistem", "label": "Pulihkan dari cadangan", "ikon": "pulih", "langkah": 5, "jenis": "pemulihan",
         "ket": "Hidupkan layanan dari salinan teruji"},
    ],
    "ddos": [
        _aksi_bukti("Rekam sampel trafik & log firewall, hitung SHA-256, catat berita acara"),
        {"id": "blokir_ip", "label": "Blokir IP anomali", "ikon": "blokir", "langkah": 1, "jenis": "pemutus",
         "ket": "Blokir sumber banjir & aktifkan penyaring trafik"},
        {"id": "mode_hemat", "label": "Mode hemat layanan", "ikon": "hemat", "langkah": 2, "jenis": "pendukung",
         "ket": "Tunda fitur non-inti, utamakan layanan inti"},
        {"id": "normalkan_kapasitas", "label": "Normalkan kapasitas", "ikon": "pulih", "langkah": 5, "jenis": "pemulihan",
         "ket": "Kembalikan kapasitas setelah trafik reda"},
    ],
    "sabotase_ot": [
        _aksi_bukti("Rekam lalu lintas Modbus, log workstation teknisi & konfigurasi pengendali, hitung SHA-256"),
        {"id": "putus_jalur_ot", "label": "Putus jalur IT–OT", "ikon": "potong", "langkah": 1, "jenis": "pemutus",
         "ket": "Webhook (simulasi) ke sakelar terkelola: putus uplink kantor → zona kendali; genset tetap menyala"},
        {"id": "cabut_akses_teknisi", "label": "Cabut akses jarak jauh", "ikon": "blokir", "langkah": 2, "jenis": "pemutus",
         "ket": "Cabut akses jarak jauh workstation teknisi & blokir alamat asal"},
        {"id": "pulihkan_jalur_ot", "label": "Pulihkan jalur kendali", "ikon": "pulih", "langkah": 5, "jenis": "pemulihan",
         "ket": "Sambungkan kembali setelah konfigurasi pengendali diperiksa"},
    ],
    "backup_dimatikan": [
        _aksi_bukti("Salin riwayat konfigurasi & jejak login, hitung SHA-256, catat berita acara"),
        {"id": "audit_konfigurasi", "label": "Audit konfigurasi", "ikon": "periksa", "langkah": 1, "jenis": "pendukung",
         "ket": "Telusuri siapa yang mengubah jadwal pencadangan"},
        {"id": "nyalakan_backup", "label": "Nyalakan ulang pencadangan", "ikon": "cadangan", "langkah": 2, "jenis": "pendukung",
         "ket": "Aktifkan pencadangan + buat salinan darurat"},
        {"id": "cabut_akses", "label": "Cabut akses & blokir IP", "ikon": "blokir", "langkah": 3, "jenis": "pemutus",
         "ket": "Kunci akun mencurigakan, blokir alamat asal"},
    ],
}


def aksi_berjenis(skenario: str, jenis: str) -> list[dict]:
    return [a for a in SOAR[skenario] if a["jenis"] == jenis]


def langkah_bukti(skenario: str) -> int:
    """Fase 4: indeks langkah AMANKAN BUKTI (selalu ada, selalu sebelum pemutusan)."""
    return next(a["langkah"] for a in SOAR[skenario] if a["jenis"] == "bukti")


def langkah_pemutus(skenario: str) -> set[int]:
    return {a["langkah"] for a in aksi_berjenis(skenario, "pemutus")}


def langkah_pemulihan(skenario: str) -> set[int]:
    """Indeks langkah playbook yang MEMULIHKAN layanan (dipakai juga untuk mengunci centang manual)."""
    return {a["langkah"] for a in aksi_berjenis(skenario, "pemulihan")}


# Aksi gabungan (F-04): "isolasi" = semua tindakan pemutus yang tersisa, berurutan;
# "pulihkan" = tindakan pemulihan, hanya bila syarat_pemulihan() terpenuhi. Aksi lama "semua" DIHAPUS.
AKSI_GABUNGAN = ["isolasi", "pulihkan"]
SEMUA_AKSI_SOAR = [a["id"] for daftar in SOAR.values() for a in daftar]
# Langkah yang dihitung sebagai "penahanan" untuk metrik MTTC
TAHAP_PENAHANAN = {"ransomware": 1, "ddos": 1, "backup_dimatikan": 3, "sabotase_ot": 1}
JEDA_RUNBOOK = 1.2  # detik antar-tindakan pemutus saat isolasi berurutan (juga: bukti → pemutus pertama)
MIN_ALASAN_DARURAT = 15   # karakter; alasan isolasi darurat tidak boleh asal "ok"

# --------------------------------------------------------------------------
# TRIASE PERINGATAN dan NILAI KESIAPAN SIBER
# --------------------------------------------------------------------------
# Peringatan terbuka = aset yang dinaikkan ke WASPADA oleh CTI dan/atau AI lokal (peluang ≥ 50%).
# Operator boleh MENUTUPNYA dengan alasan tertulis: "selesai" (ancaman sudah ditangani) atau
# "false_positive" (alarm ternyata bukan ancaman). Penutupan TIDAK menghapus apa pun: berita CTI dan
# penilaian AI tetap tercatat; yang berubah hanya bahwa SUMBER-SUMBER saat itu tidak lagi menaikkan aset
# tersebut. Bukti baru (berita lain, atau episode anomali AI berikutnya) membuka peringatan lagi.
# Setiap penutupan menjadi halaman baru di buku rantai bukti (HMAC berantai) + log audit.
MIN_ALASAN_TUTUP = 15
STATUS_TUTUP = {"selesai": "tutup_selesai", "false_positive": "tutup_fp"}   # status → kunci label di ISTILAH
# Nilai kesiapan siber per layanan (kelompok aset), 0–100, makin tinggi makin siap. Rumus sengaja sederhana
# dan terbuka agar bisa diperiksa juri (lihat Dokumentasi Teknis §2.5):
#   Kerawanan = 100 − 50 × rata-rata peluang serangan aset − 30 × porsi aset bertemuan konfigurasi
#               − 20 × (backup terlambat atau belum diuji)
#   Insiden   = 100 − 70 (insiden belum ditahan) atau − 40 (sudah ditahan, belum pulih)
#               − 15 per peringatan WASPADA terbuka (maks. 30)
#   Nilai     = yang LEBIH RENDAH dari keduanya (rantai sekuat mata rantai terlemah).
# Nilai posko = rata-rata tertimbang jumlah aset; selama ada insiden belum ditahan, paling tinggi D.
BOBOT_KERAWANAN = {"peluang": 50, "temuan": 30, "backup": 20}
POTONG_INSIDEN = {"aktif": 70, "ditahan": 40, "peringatan": 15, "maks_peringatan": 30}
BATAS_HURUF = ((90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "E"))
PLAFON_INSIDEN_AKTIF = 59   # nilai posko tertinggi selama ada insiden yang belum ditahan (= D)


def huruf_nilai(nilai: float) -> str:
    return next(h for batas, h in BATAS_HURUF if nilai >= batas)

INFO_RUTIN = [
    "Pemindaian rutin selesai: tidak ada port baru yang terbuka",
    "Sinkronisasi waktu server berhasil",
    "Sertifikat TLS portal web masih berlaku (sintetis)",
    "Replikasi basis data berjalan normal",
    "Pengingat: port RDP 192.0.2.90 masih terbuka",
]


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sudut_dari(teks: str) -> float:
    """Sudut radar yang stabil dari alamat IP (hash → 0..2π)."""
    h = int.from_bytes(hashlib.sha256(teks.encode()).digest()[:4], "big")
    return round((h % 3600) / 3600 * 2 * math.pi, 4)


def efek_langkah() -> dict[str, list[str | None]]:
    return {s: [DAMPAK[s]["langkah"].get(i, {}).get("ket") for i in range(len(PLAYBOOK[s]))]
            for s in DAMPAK}


def label_peluang(p: float) -> str:
    return "sangat tinggi" if p >= .75 else "tinggi" if p >= .5 else "sedang" if p >= .3 else "rendah"


# --------------------------------------------------------------------------
# 4. RADIO SATPAM: generator berita ancaman sintetis (OSINT/CTI)
# --------------------------------------------------------------------------
class GeneratorOSINT:
    """Menyiarkan berita ancaman sintetis secara berkala.
    Berita punya umur (ttl): segar di awal, lalu memudar dan kedaluwarsa,
    persis seperti kabar di radio yang makin lama makin tidak relevan."""

    def __init__(self, jam: Callable[[], float], acak: random.Random):
        self._jam, self._acak = jam, acak
        self.reset()

    def reset(self) -> None:
        self.aktif: list[dict] = []
        self.riwayat: deque[dict] = deque(maxlen=12)
        self.berikut = self._jam() + CTI_PERTAMA
        self._terakhir: str | None = None

    def _pilih(self) -> dict:
        aktif_id = {a["id"] for a in self.aktif}
        kandidat = [b for b in BERITA_ANCAMAN if b["id"] not in aktif_id and b["id"] != self._terakhir]
        relevan = [b for b in kandidat if set(b["port"]) & PORT_INVENTARIS]
        # 80% berita relevan dengan aset kita, 20% tidak (agar terlihat bahwa sistem MENYARING)
        kolam = relevan if relevan and self._acak.random() < 0.8 else kandidat
        return self._acak.choice(kolam)

    def siarkan(self, berita_id: str | None = None) -> dict:
        b = INDEKS_BERITA[berita_id] if berita_id else self._pilih()
        self.aktif = [a for a in self.aktif if a["id"] != b["id"]]   # siaran ulang = segarkan
        if len(self.aktif) >= MAKS_CTI_AKTIF:
            self.aktif.pop(0)                                        # yang paling lama tergeser
        sekarang = self._jam()
        item = {**b, "terbit_mono": sekarang, "habis_mono": sekarang + b["ttl"], "terbit": _iso()}
        self.aktif.append(item)
        self._terakhir = b["id"]
        self.berikut = sekarang + JEDA_CTI
        return item

    def kesegaran(self, a: dict) -> float:
        """1.0 selama 60% umur pertama, lalu turun linear ke 0 saat kedaluwarsa."""
        f = (self._jam() - a["terbit_mono"]) / a["ttl"]
        return 1.0 if f < 0.6 else max(0.0, (1 - f) / 0.4)

    def detak(self) -> tuple[list[dict], list[dict]]:
        sekarang = self._jam()
        habis = [a for a in self.aktif if a["habis_mono"] <= sekarang]
        self.aktif = [a for a in self.aktif if a["habis_mono"] > sekarang]
        baru = [self.siarkan()] if sekarang >= self.berikut else []
        return baru, habis


# --------------------------------------------------------------------------
# 5. MENARA PEMANTAU (dapur)
# --------------------------------------------------------------------------
class Menara:
    def __init__(self, jam: Callable[[], float] = time.monotonic, acak: random.Random | None = None):
        self._jam = jam
        self._acak = acak or random.Random()
        self._seq = 0
        self.versi = 0
        self._efek = efek_langkah()
        self._pencacah: PencacahIR = PENCACAH          # F-03: TIDAK ikut reset()
        self.saat_ir: Callable[[dict], None] | None = None   # kait: main.py mencatatnya ke log audit
        self.saat_ubah: Callable[[], None] | None = None     # Fase 2 (R1): kait untuk membangunkan dapur
        self.rantai: RantaiBukti = RANTAI                    # Fase 4: TIDAK ikut reset() (tambah-saja)
        self.saat_bukti: Callable[[str, str, dict], None] | None = None   # kait: cermin ke log audit
        self.osint = GeneratorOSINT(lambda: self._jam(), self._acak)
        self.deteksi = MesinDeteksi()                        # mesin deteksi aturan (app/deteksi.py)
        self.reset()

    # -- siklus hidup -------------------------------------------------------
    def reset(self) -> None:
        self.versi += 1
        self.beban = BEBAN_DASAR["target"]
        self.riwayat: deque[float] = deque(maxlen=PANJANG_RIWAYAT)
        self._detak_terakhir = self._jam()
        self._linimasa: deque[dict] = deque(self._benih_linimasa(), maxlen=MENIT_LINIMASA)
        self._ember: list[float] = []                  # linimasa: beban tiap detik pada menit berjalan
        self._ember_insiden = False
        self._ember_ai: dict[str, str] = {}             # linimasa: aset yang dinilai AI tidak wajar pada menit berjalan
        self._posko_sejak = _iso()                      # KPI: posko aktif sejak (reset terakhir)
        self._jumlah_insiden = 0                        # KPI: insiden sejak posko aktif
        self._mttc_semua: list[int] = []                # KPI: semua waktu penahanan sejak posko aktif (detik)
        self._peristiwa: deque[dict] = deque(maxlen=80)
        self._antre: list[tuple[float, dict]] = []
        self._info_berikut = self._jam() + JEDA_INFO_RUTIN
        self.osint.reset()
        self._diperketat: set[str] = set()
        self._antre_soar: list[tuple[float, str, str]] = []   # (waktu, layanan_id, aksi_id)
        self._mulai_insiden: dict[str, float] = {}
        self._mttc: dict[str, dict] = {}
        self._tanda_cti: tuple = ()
        self._panggilan: dict[str, list[dict]] = {}   # v4: riwayat panggilan darurat per lembaga
        self._ir: list[dict] = []                     # laporan terkirim (terbaru di akhir)
        self._ir_insiden: dict[str, dict] = {}        # laporan per insiden aktif
        self._jejak: dict[str, dict[int, dict]] = {}  # F-02: bukti tiap langkah {indeks: {metode, label, detik, waktu, oleh}}
        self._perintah_isolasi: dict[str, str] = {}  # akun yang menahan tombol isolasi (aktor tindakan SOAR berantai)
        self._sebab: dict[str, str] = {}              # v5: simpul topologi → layanan penyebab status
        self._bukti: dict[str, dict] = {}             # Fase 4: bukti yang diamankan per insiden aktif
        self._darurat: dict[str, dict] = {}           # Fase 4: isolasi darurat (beralasan) per insiden aktif
        self._injeksi_ai: dict[str, tuple[str, float]] = {}   # AI: aset → (pola latihan, berakhir)
        self._tanda_ai: frozenset[str] = frozenset()        # AI: aset yang sedang dinilai tidak wajar
        self._ai_sejak: dict[str, float] = {}               # AI: kapan anomali aset pertama terlihat
        self._ditutup: dict[str, dict] = {}                 # triase: aset → sumber yang sudah ditutup Operator
        self._hitung_tutup = {s: 0 for s in STATUS_TUTUP}   # triase: jumlah penutupan per status (sesi demo)
        self._riwayat_tutup: deque[dict] = deque(maxlen=5)  # triase: penutupan terakhir (terbaru di depan)
        self.deteksi.reset()
        self._antre_det: list[tuple[float, dict]] = []     # deteksi: peristiwa mentah latihan yang menunggu waktunya
        self._meta_insiden: dict[str, dict] = {}            # peringatan: judul & waktu mulai insiden aktif
        self._riwayat_insiden: deque[dict] = deque(maxlen=5)  # peringatan: insiden yang sudah dipulihkan
        self._respons: dict[str, dict] = {}                 # drill: jejak respons per layanan (tetap ada setelah pulih)
        self.catat("info", "Pemantauan jaringan dimulai. Semua data adalah data sintetis.")

    def ubah(self) -> None:
        """Naikkan nomor versi DAN bangunkan dapur (bila sedang berjalan), supaya perubahan
        disiarkan dalam ≈50 ms tanpa menunggu detak berikutnya. Aman dipanggil dari thread mana pun."""
        self.versi += 1
        if self.saat_ubah:
            self.saat_ubah()

    # -- buku peristiwa -------------------------------------------------------
    def _entri(self, tingkat, pesan, rel_menit, layanan, jenis="umum") -> dict:
        self._seq += 1
        return {"seq": self._seq, "waktu": _iso(), "tingkat": tingkat, "pesan": pesan,
                "rel_menit": rel_menit, "layanan": layanan, "jenis": jenis}

    def catat(self, tingkat: str, pesan: str, rel_menit: int | None = None,
              layanan: str | None = None, jenis: str = "umum") -> None:
        self._peristiwa.append(self._entri(tingkat, pesan, rel_menit, layanan, jenis))

    # ======================================================================
    # THREAT INTELLIGENCE: korelasi proaktif
    # ======================================================================
    def _sektor_kita(self, layanan: dict) -> set[str]:
        return {l["sektor"] for l in layanan.values()}

    def _bobot(self, aset: dict, berita: dict, sektor_kita: set[str]) -> float:
        """Kontribusi SATU berita ke peluang serangan SATU aset.
        bobot = keyakinan sumber × paparan aset × bonus sektor × kesegaran berita × (pengerasan)"""
        if aset["port"] not in berita["port"]:
            return 0.0
        w = berita["keyakinan"] * aset["paparan"] * self.osint.kesegaran(berita)
        if berita["sektor"] in sektor_kita:
            w *= BONUS_SEKTOR
        if aset["id"] in self._diperketat:
            w *= FAKTOR_PERKETAT
        return min(w, 0.97)

    # ======================================================================
    # AI LOKAL: mesin deteksi anomali (Isolation Forest, app/ai_anomali.py)
    # ======================================================================
    def _status_insiden(self, layanan: dict) -> dict[str, tuple[str, str]]:
        """Status perangkat yang disebabkan insiden aktif (setelah efek langkah playbook): {id: (status, skenario)}."""
        hasil: dict[str, tuple[str, str]] = {}
        for l in layanan.values():
            ins = l["insiden"]
            if not ins:
                continue
            d = DAMPAK[ins["skenario"]]
            peta = dict(d["perangkat"])
            for i, beres in enumerate(ins["langkah_selesai"]):
                if beres:
                    peta.update(d["langkah"].get(i, {}).get("perangkat", {}))
            for pid, (st, _) in peta.items():
                if pid not in hasil or PERINGKAT[st] > PERINGKAT[hasil[pid][0]]:
                    hasil[pid] = (st, ins["skenario"])
        return hasil

    def _ai(self, layanan: dict) -> dict:
        """Ciri lalu lintas tiap aset → skor anomali. Aset terisolasi tidak dinilai (lalu lintasnya diputus)."""
        sekarang = self._jam()
        insiden = self._status_insiden(layanan)
        ciri: dict[str, tuple[float, ...]] = {}
        for aid in ASET_BERPORT:
            inj = self._injeksi_ai.get(aid)
            st, sken = insiden.get(aid, ("normal", ""))
            if st == "isolasi":
                continue
            if inj and inj[1] > sekarang:
                ciri[aid] = ciri_pola(inj[0])
            elif st in ("kritis", "waspada") and sken:
                pola = POLA_SKENARIO[sken]
                if sken == "sabotase_ot" and INDEKS_SIMPUL[aid]["port"] != 502:
                    pola = "akses_jarak_jauh"
                ciri[aid] = ciri_pola(pola)
            else:
                ciri[aid] = ciri_normal(aid)
        modbus = {aid for aid in ciri if INDEKS_SIMPUL[aid]["port"] == 502}
        return DETEKTOR.nilai(ciri, modbus)

    def latihan_ai(self, layanan: dict, aset_id: str, pola: str | None = None) -> dict:
        """Latihan: suntikkan pola lalu lintas tidak wajar (data sintetis) ke satu aset, lalu lihat AI menilainya."""
        s = INDEKS_SIMPUL[aset_id]
        pola = pola or ("modbus_tulis_asing" if s["port"] == 502 else "eksfiltrasi")
        if pola not in POLA:
            raise ValueError("Pola latihan tidak dikenal")
        self._injeksi_ai[aset_id] = (pola, self._jam() + DURASI_LATIHAN_AI)
        if aset_id in self._ditutup:              # latihan baru = episode baru: penutupan AI lama tidak berlaku
            self._ditutup[aset_id]["ai_sejak"] = None
        self.catat("info", f"Latihan AI: pola \"{POLA[pola]['nama']}\" disuntikkan ke lalu lintas {s['nama']} "
                           f"{s['ip']}:{s['port']} (data sintetis, {DURASI_LATIHAN_AI // 60} menit)", jenis="ai")
        self._periksa_ai(layanan)
        self.ubah()
        h = self._ai(layanan).get(aset_id)
        pr = self._prediksi(layanan).get(aset_id, {})
        return {"aset_id": aset_id, "pola": pola, "skor": h.skor if h else None,
                "anomali": bool(h and h.anomali), "alasan": h.alasan if h else "", "persen": pr.get("persen")}

    def _periksa_ai(self, layanan: dict) -> None:
        """Catat perubahan penilaian AI di log (sekali per perubahan, bukan tiap detik)."""
        sekarang = self._jam()
        for aid in [a for a, (_, akhir) in self._injeksi_ai.items() if akhir <= sekarang]:
            del self._injeksi_ai[aid]
        hasil = self._ai(layanan)
        tanda = frozenset(a for a, h in hasil.items() if h.anomali)
        for aid in tanda:
            self._ember_ai.setdefault(aid, hasil[aid].alasan)
        if tanda == self._tanda_ai:
            return
        for aid in sorted(tanda - self._tanda_ai):
            s, h = INDEKS_SIMPUL[aid], hasil[aid]
            self._ai_sejak[aid] = sekarang
            self.catat("sedang", f"AI lokal ▶ lalu lintas tidak wajar di {s['nama']} {s['ip']}:{s['port']} — "
                                 f"skor anomali {f'{h.skor:.2f}'.replace('.', ',')} ({h.alasan})", jenis="ai")
        for aid in sorted(self._tanda_ai - tanda):
            self._ai_sejak.pop(aid, None)
            self.catat("info", f"AI lokal: lalu lintas {INDEKS_SIMPUL[aid]['nama']} kembali wajar", jenis="ai")
        self._tanda_ai = tanda
        self.ubah()

    def _prediksi(self, layanan: dict) -> dict[str, dict]:
        """Peluang gabungan: 1 − Π(1 − bobot_i) dari semua berita CTI, DIGABUNG dengan peluang AI:
        p = 1 − (1 − p_CTI)(1 − p_AI). Artinya: 'berapa peluang SETIDAKNYA satu tanda bahaya benar'.
        Aset yang sedang ditangani insiden tidak diberi prediksi AI (statusnya sudah ditentukan playbook)."""
        sektor_kita = self._sektor_kita(layanan)
        ai = self._ai(layanan)
        dalam_insiden = set(self._status_insiden(layanan))
        hasil: dict[str, dict] = {}
        for aid in ASET_BERPORT:
            s = INDEKS_SIMPUL[aid]
            sisa, sumber = 1.0, []
            tutup = self._ditutup.get(aid, {})
            for b in self.osint.aktif:
                if b["id"] in tutup.get("berita", ()):
                    continue              # triase: berita ini sudah ditutup Operator untuk aset ini
                w = self._bobot(s, b, sektor_kita)
                if w > 0:
                    sisa *= 1 - w
                    sumber.append(b["id"])
            info_det = []
            if aid not in dalam_insiden:
                for tm in self.deteksi.aktif(self._jam()):
                    if aid not in tm.aset or tm.id in tutup.get("deteksi", ()):
                        continue
                    p_det = tm.peluang * (FAKTOR_PERKETAT if aid in self._diperketat else 1)
                    sisa *= 1 - p_det
                    sumber.append(tm.id)
                    info_det.append({"id": tm.id, "nama": tm.nama, "persen": round(p_det * 100),
                                     "alasan": tm.alasan(), "keparahan": tm.keparahan})
            info_ai = None
            h = ai.get(aid)
            ai_ditutup = tutup.get("ai_sejak") is not None and tutup["ai_sejak"] == self._ai_sejak.get(aid)
            if h and h.anomali and aid not in dalam_insiden and not ai_ditutup:
                p_ai = h.peluang * (FAKTOR_PERKETAT if aid in self._diperketat else 1)
                sisa *= 1 - p_ai
                sumber.append(SUMBER_AI)
                info_ai = {"skor": h.skor, "persen": round(p_ai * 100), "alasan": h.alasan}
            if sumber:
                p = 1 - sisa
                hasil[aid] = {"id": aid, "nama": s["nama"], "ip": s["ip"], "port": s["port"],
                              "prob": round(p, 3), "persen": round(p * 100), "tingkat": label_peluang(p),
                              "sumber": sumber, "diperketat": aid in self._diperketat,
                              "proaktif": p >= AMBANG_PROAKTIF, "ai": info_ai, "deteksi": info_det}
        return hasil

    def _korelasi_berita(self, berita: dict, layanan: dict) -> list[dict]:
        sektor_kita = self._sektor_kita(layanan)
        hasil = []
        for aid in ASET_BERPORT:
            w = self._bobot(INDEKS_SIMPUL[aid], berita, sektor_kita)
            if w > 0:
                hasil.append({"id": aid, "nama": INDEKS_SIMPUL[aid]["nama"], "persen": round(w * 100)})
        return hasil

    def _umumkan(self, berita: dict, layanan: dict) -> None:
        korelasi = self._korelasi_berita(berita, layanan)
        berita["korelasi"] = korelasi                    # disimpan untuk ticker
        self.osint.riwayat.appendleft({k: berita[k] for k in ("id", "sumber", "judul", "port", "sektor",
                                                              "keyakinan", "terbit", "korelasi")})
        self.catat("sedang" if korelasi else "info",
                   f"CTI {berita['id']} · {berita['sumber']}: {berita['judul']}", jenis="cti")
        if korelasi:
            for k in korelasi:
                s = INDEKS_SIMPUL[k["id"]]
                tanda = "→ dinaikkan ke WASPADA" if k["persen"] >= AMBANG_PROAKTIF * 100 else "→ dipantau"
                self.catat("sedang" if k["persen"] >= AMBANG_PROAKTIF * 100 else "info",
                           f"Korelasi {berita['id']}: cocok dengan {s['nama']} {s['ip']}:{s['port']} "
                           f"— peluang serangan {k['persen']}% {tanda}", jenis="cti")
        else:
            port = ", ".join(str(p) for p in berita["port"])
            self.catat("info", f"Korelasi {berita['id']}: tidak ada aset dengan port {port} di inventaris "
                               "— dicatat, tidak ada tindakan", jenis="cti")

    def siarkan_berita(self, layanan: dict, berita_id: str | None = None) -> dict:
        item = self.osint.siarkan(berita_id)
        self._umumkan(item, layanan)
        self.ubah()
        return item

    # ======================================================================
    # INSIDEN, LANGKAH PLAYBOOK, SOAR
    # ======================================================================
    def insiden_dimulai(self, layanan: dict, layanan_id: str, skenario: str, judul: str,
                        log: list[tuple[int, str, str]]) -> None:
        nama = layanan[layanan_id]["nama"]
        attck = ringkas_mitre(skenario)
        self.catat("sedang", f"Latihan dimulai: {judul} di {nama}. Memutar ulang kronologi gejala…"
                             + (f" [ATT&CK {attck}]" if attck else ""), layanan=layanan_id)
        mulai = self._jam()
        self._mulai_insiden[layanan_id] = mulai
        self._jumlah_insiden += 1
        self._meta_insiden[layanan_id] = {"judul": judul, "nama": nama, "skenario": skenario, "mulai": _iso()}
        self._mttc.pop(layanan_id, None)
        self._respons[layanan_id] = {"bukti_detik": None, "bukti_nomor": None, "darurat_detik": None,
                                     "mttc_detik": None, "mttc_metode": None, "bukti_cocok": None, "pulih_detik": None}
        self._ir_insiden.pop(layanan_id, None)        # insiden baru = laporan baru
        self._jejak.pop(layanan_id, None)
        self._perintah_isolasi.pop(layanan_id, None)
        self._bukti.pop(layanan_id, None)
        self._darurat.pop(layanan_id, None)
        for i, (menit, tingkat, pesan) in enumerate(log, start=1):
            self._antre.append((mulai + 0.7 * i, {"tingkat": tingkat, "pesan": pesan,
                                                  "rel_menit": menit, "layanan": layanan_id}))
        # Apakah intelijen sudah memperingatkan aset yang kini diserang?
        prediksi = self._prediksi(layanan)
        sasaran = [pid for pid, (st, _) in DAMPAK[skenario]["perangkat"].items() if st == "kritis"]
        for pid in sasaran:
            pr = prediksi.get(pid)
            if pr and pr["proaktif"]:
                umur_cti = [mulai - a["terbit_mono"] for a in self.osint.aktif if a["id"] in pr["sumber"]]
                if SUMBER_AI in pr["sumber"] and pid in self._ai_sejak:
                    umur_cti.append(mulai - self._ai_sejak[pid])
                umur_cti += [mulai - tm.mulai for tm in self.deteksi.temuan if tm.id in pr["sumber"]]
                umur = min(umur_cti, default=0)
                self.catat("info", f"Peringatan dini terbukti: {', '.join(pr['sumber'])} memprediksi risiko "
                                   f"{pr['nama']} ({pr['persen']}%) {round(umur)} detik sebelum serangan",
                           layanan=layanan_id, jenis="cti")
        self.ubah()

    def _parameter(self, layanan: dict) -> dict:
        hasil = dict(BEBAN_DASAR)
        for l in layanan.values():
            ins = l["insiden"]
            if not ins:
                continue
            d = DAMPAK[ins["skenario"]]
            p = {"target": d["target"], "goyang": d["goyang"], "lonjakan": d["lonjakan"]}
            for i, beres in enumerate(ins["langkah_selesai"]):
                if beres:
                    efek = d["langkah"].get(i, {})
                    p.update({k: efek[k] for k in ("target", "lonjakan") if k in efek})
            if p["target"] > hasil["target"]:
                hasil = p
        return hasil

    def catat_langkah(self, layanan: dict, layanan_id: str, indeks: int, selesai: bool,
                      metode: str = "manual", label: str | None = None, oleh: str | None = None) -> None:
        """Satu pintu untuk mencentang langkah, baik oleh manusia maupun SOAR. Jejaknya mencatat KAPAN (UTC) dan
        OLEH SIAPA: untuk tindakan SOAR berantai, aktornya adalah akun yang menahan tombol isolasi."""
        l = layanan[layanan_id]
        ins = l["insiden"]
        ins["langkah_selesai"][indeks] = selesai
        jejak = self._jejak.setdefault(layanan_id, {})
        if selesai:
            jejak[indeks] = {"metode": metode, "label": label or ins["langkah"][indeks].split(":")[0],
                             "detik": self._detik_insiden(layanan_id), "waktu": _iso(), "oleh": oleh}
        else:
            jejak.pop(indeks, None)
        judul = ins["langkah"][indeks].split(":")[0]
        efek = DAMPAK[ins["skenario"]]["langkah"].get(indeks, {})
        if metode == "soar":
            self.catat("info", f"SOAR ▶ {label} selesai otomatis di {l['nama']}"
                               + (f" — {efek['ket']}" if efek.get("ket") else ""),
                       layanan=layanan_id, jenis="soar")
        else:
            self.catat("info" if selesai else "sedang",
                       f"Langkah {indeks + 1} playbook {l['nama']} {'selesai' if selesai else 'dibatalkan'}: {judul}",
                       layanan=layanan_id)
        if selesai:
            # Efek langsung terasa: beban tidak menunggu "turun pelan", tetapi dipotong seketika
            p = self._parameter(layanan)
            if self.beban > p["target"] + 3:
                self.beban = p["target"] + self._acak.uniform(0, 3)
                self.riwayat.append(round(self.beban, 1))
            # Metrik waktu penahanan (Mean Time To Contain)
            if indeks == TAHAP_PENAHANAN[ins["skenario"]] and layanan_id not in self._mttc \
                    and layanan_id in self._mulai_insiden:
                detik = round(self._jam() - self._mulai_insiden[layanan_id])
                self._mttc[layanan_id] = {"detik": detik, "metode": metode}
                self._jejak_respons(layanan_id, mttc_detik=detik, mttc_metode=metode)
                self._mttc_semua.append(detik)
                self.catat("info", f"Waktu penahanan (MTTC) {l['nama']}: {detik} detik "
                                   f"({'otomatis lewat SOAR' if metode == 'soar' else 'manual'})",
                           layanan=layanan_id, jenis="soar")
            self._cek_laporan(layanan, layanan_id)    # F-02: laporan hanya setelah SEMUA pemutus selesai
        self.ubah()

    def _detik_insiden(self, layanan_id: str) -> int:
        return round(self._jam() - self._mulai_insiden.get(layanan_id, self._jam()))

    def syarat_pemulihan(self, layanan: dict, layanan_id: str) -> str | None:
        """F-04: alasan pemulihan BELUM boleh dijalankan, atau None bila sudah boleh.
        Syarat: (1) aset sudah terisolasi penuh = laporan sudah terkirim,
                (2) Fase 4: bukti sudah diamankan DAN sidik jarinya masih cocok, dan
                (3) semua langkah playbook SEBELUM langkah pemulihan sudah dicentang."""
        ins = layanan[layanan_id]["insiden"]
        if not ins:
            return "Tidak ada insiden aktif di layanan ini"
        pulih = langkah_pemulihan(ins["skenario"])
        if not pulih:
            return "Skenario ini tidak memiliki tindakan pemulihan otomatis"
        if layanan_id not in self._ir_insiden:
            return (f"Belum terisolasi: jalankan isolasi dan tunggu {ISTILAH['laporan']} terkirim "
                    "sebelum memulihkan")
        alasan_bukti = self._alasan_bukti_pulih(layanan_id)
        if alasan_bukti:
            return alasan_bukti
        kurang = [str(i + 1) for i in range(min(pulih)) if not ins["langkah_selesai"][i]]
        if kurang:
            return f"Centang dulu langkah playbook {', '.join(kurang)} sebelum memulihkan"
        return None

    def jalankan_soar(self, layanan: dict, layanan_id: str, aksi_id: str, oleh: str = "sistem") -> dict:
        """Tombol tindakan cepat. Melempar ValueError bila aksi tidak sah untuk keadaan insiden.
        Kunci 'ir' di hasil = laporan yang LAHIR karena permintaan ini (None bila belum/tidak ada)."""
        self._proses_antre_soar(layanan)    # keputusan diambil atas keadaan TERKINI, bukan detak terakhir
        ins = layanan[layanan_id]["insiden"]
        if not ins:
            raise ValueError("Tidak ada insiden aktif di layanan ini")
        katalog = SOAR[ins["skenario"]]
        antre = {a for _, lid, a in self._antre_soar if lid == layanan_id}
        sudah_ada_ir = layanan_id in self._ir_insiden

        if aksi_id == "isolasi":
            sisa = [a for a in aksi_berjenis(ins["skenario"], "pemutus")
                    if not ins["langkah_selesai"][a["langkah"]] and a["id"] not in antre]
            if not sisa:
                raise ValueError("Semua tindakan pemutus untuk insiden ini sudah dijalankan")
            # Fase 4: bukti DULU. Gagal = ValueError (409) dan TIDAK ada satu kabel pun yang diputus.
            bukti_baru = layanan_id not in self._bukti and layanan_id not in self._darurat
            if bukti_baru:
                self.amankan_bukti(layanan, layanan_id, oleh, "soar")
            self.catat("sedang", f"SOAR: isolasi dimulai untuk {layanan[layanan_id]['nama']} "
                                 f"(bukti {self._bukti[layanan_id]['nomor'] if layanan_id in self._bukti else 'BELUM ADA'}"
                                 f" → {len(sisa)} tindakan pemutus berurutan; "
                                 f"{ISTILAH['laporan']} menyusul setelah semuanya selesai)",
                       layanan=layanan_id, jenis="soar")
            self._perintah_isolasi[layanan_id] = oleh
            self._jadwalkan_pemutus(layanan, layanan_id, sisa, JEDA_RUNBOOK if bukti_baru else 0.0)
            dijadwalkan = (["amankan_bukti"] if bukti_baru else []) + [a["id"] for a in sisa]
        else:
            if aksi_id == "pulihkan":
                aksi = next((a for a in aksi_berjenis(ins["skenario"], "pemulihan")
                             if not ins["langkah_selesai"][a["langkah"]]), None)
                if aksi is None:
                    raise ValueError(self.syarat_pemulihan(layanan, layanan_id) or "Pemulihan sudah dijalankan")
            else:
                aksi = next((a for a in katalog if a["id"] == aksi_id), None)
                if aksi is None:
                    raise ValueError("Tindakan ini tidak berlaku untuk skenario insiden tersebut")
            if ins["langkah_selesai"][aksi["langkah"]]:
                raise ValueError("Tindakan ini sudah dijalankan")
            if aksi["jenis"] == "bukti":
                self.amankan_bukti(layanan, layanan_id, oleh, "soar")
            else:
                if aksi["jenis"] == "pemutus":
                    alasan = self.alasan_tolak_pemutusan(layanan_id)
                    if alasan:
                        raise ValueError(alasan)
                if aksi["jenis"] == "pemulihan":
                    alasan = self.syarat_pemulihan(layanan, layanan_id)
                    if alasan:
                        raise ValueError(alasan)
                    self.verifikasi_untuk_pemulihan(layanan, layanan_id, oleh)
                self.catat_langkah(layanan, layanan_id, aksi["langkah"], True, "soar", aksi["label"], oleh)
            dijadwalkan = [aksi["id"]]
        self.ubah()
        lahir = None if sudah_ada_ir else self._ir_insiden.get(layanan_id)
        return {"dijadwalkan": dijadwalkan, "ir": lahir,
                "ir_menunggu": layanan_id not in self._ir_insiden
                               and any(lid == layanan_id for _, lid, _a in self._antre_soar)}

    def _proses_antre_soar(self, layanan: dict) -> None:
        sekarang = self._jam()
        siap = [x for x in self._antre_soar if x[0] <= sekarang]
        self._antre_soar = [x for x in self._antre_soar if x[0] > sekarang]
        for _, lid, aksi_id in siap:
            ins = layanan.get(lid, {}).get("insiden")
            if not ins:
                continue                          # insiden sudah ditutup di tengah jalan
            aksi = next((a for a in SOAR[ins["skenario"]] if a["id"] == aksi_id), None)
            if aksi and not ins["langkah_selesai"][aksi["langkah"]]:
                if aksi["jenis"] == "pemutus" and self.alasan_tolak_pemutusan(lid):
                    # Pertahanan berlapis: antrean pun tidak boleh memutus tanpa bukti / darurat
                    self.catat("kritis", f"SOAR ✖ {aksi['label']} dibatalkan: bukti belum diamankan",
                               layanan=lid, jenis="soar")
                    continue
                self.catat_langkah(layanan, lid, aksi["langkah"], True, "soar", aksi["label"],
                                   self._perintah_isolasi.get(lid))

    # ======================================================================
    # v5.1: AUTOMATED IR BLAST & QUICK CALL (Pre-Authorized Containment)
    # ======================================================================
    def _cek_laporan(self, layanan: dict, layanan_id: str) -> None:
        """F-02: kirim laporan TEPAT SEKALI, dan hanya bila SEMUA langkah pemutus sudah selesai
        (dijalankan SOAR maupun dicentang manusia). Tindakan yang masih antre = belum fakta."""
        ins = layanan[layanan_id]["insiden"]
        if not ins or layanan_id in self._ir_insiden:
            return
        pemutus = aksi_berjenis(ins["skenario"], "pemutus")
        if pemutus and all(ins["langkah_selesai"][a["langkah"]] for a in pemutus):
            self._kirim_ir(layanan, layanan_id, pemutus)

    def _kirim_ir(self, layanan: dict, layanan_id: str, aksi_pemutus: list[dict]) -> dict:
        """Laporan otomatis ke manajemen — DIKIRIM, bukan dimintakan izin.
        SIMULASI: tidak ada email/pesan yang keluar dari server; hanya dicatat di log & audit."""
        l = layanan[layanan_id]
        ins = l["insiden"]
        nomor, uid = self._pencacah.berikutnya(ISTILAH["laporan_singkat"])
        jejak = self._jejak.get(layanan_id, {})
        rincian = [{"id": a["id"], "label": a["label"], "status": "selesai",
                    "metode": jejak.get(a["langkah"], {}).get("metode", "manual"),
                    "detik": jejak.get(a["langkah"], {}).get("detik")} for a in aksi_pemutus]
        detik = self._detik_insiden(layanan_id)
        ir = {
            "nomor": nomor, "uuid": uid, "jenis": ISTILAH["laporan"],
            "keparahan": KEPARAHAN_IR[ins["skenario"]], "waktu": _iso(), "detik": detik,
            "layanan_id": layanan_id, "aset": l["nama"], "cabang": l["cabang"], "insiden": ins["judul"],
            "tindakan": [r["label"] for r in rincian], "rincian": rincian, "kebijakan": KEBIJAKAN["kode"],
            "kepada": nama_manajemen(), "status": "TERKIRIM (simulasi)",
            # Fase 4: rujukan berita acara bukti, dan alasan bila jaringan diputus tanpa bukti
            "bukti": self._ringkas_bukti(layanan_id),
            "darurat": ({k: self._darurat[layanan_id][k] for k in ("alasan", "petugas", "waktu", "hash_buku")}
                        if layanan_id in self._darurat else None),
        }
        self._ir.append(ir)
        del self._ir[:-10]
        self._ir_insiden[layanan_id] = ir
        jejak_teks = ", ".join(f"{r['label']} T+{r['detik']}" for r in rincian)
        catatan_bukti = (f" · {ISTILAH['tombol_darurat']}: {ir['darurat']['alasan']}" if ir["darurat"]
                         else f" · bukti {ir['bukti']['nomor']}" if ir["bukti"] else "")
        self.catat("info", f"{nomor} {ir['keparahan']} → {' & '.join(ir['kepada'])}: {l['nama']} terisolasi "
                           f"({jejak_teks}) · dilaporkan T+{detik} dtk{catatan_bukti}", layanan=layanan_id, jenis="ir")
        # Langkah "LAPOR" di playbook otomatis tercentang: laporan sudah terkirim
        ins["langkah_selesai"][LANGKAH_IR[ins["skenario"]]] = True
        if self.saat_ir:
            self.saat_ir(ir)
        return ir

    def panggil(self, layanan: dict, layanan_id: str, oleh: str) -> dict:
        """QUICK CALL ke PIC teknis cabang — KOORDINASI, bukan meminta izin.
        Tujuannya agar admin cabang tidak panik mengira server mati lalu me-restart-nya.
        Tidak ada panggilan sungguhan: hanya dicatat (siapa, kapan) agar bisa diaudit."""
        pic = PROFIL_LAYANAN[layanan_id]["pic"]
        ins = layanan[layanan_id]["insiden"]
        pesan = (pesan_jangan_restart() if layanan_id in self._ir_insiden
                 else "insiden aktif, siaga isolasi" if ins else "koordinasi rutin")
        entri = {"nama": pic["nama"], "jabatan": pic["jabatan"], "cabang": pic["cabang"], "kanal": pic["kanal"],
                 "pesan": pesan, "waktu": _iso(), "oleh": oleh}
        riwayat = self._panggilan.setdefault(layanan_id, [])
        riwayat.append(entri)
        del riwayat[:-10]
        self.catat("info", f"{ISTILAH['quick_call']} → {pic['jabatan']} {pic['cabang']} ({pic['nama']}): {pesan} — simulasi",
                   layanan=layanan_id, jenis="komando")
        self.ubah()
        return entri

    # ======================================================================
    # Fase 4: RANTAI BUKTI FORENSIK & ISOLASI DARURAT
    # ======================================================================
    def _cermin(self, petugas: str, aksi: str, detail: dict) -> None:
        """Setiap halaman buku rantai bukti juga dicatat ke log audit HMAC (kait dipasang main.py)."""
        if self.saat_bukti:
            self.saat_bukti(petugas, aksi, detail)

    def _ringkas_bukti(self, layanan_id: str) -> dict | None:
        b = self._bukti.get(layanan_id)
        return {k: b[k] for k in ("nomor", "sha256", "hash_buku", "susulan")} if b else None

    def alasan_tolak_pemutusan(self, layanan_id: str) -> str | None:
        """None = boleh memutus jaringan. Syarat: bukti sudah diamankan ATAU isolasi darurat dipicu."""
        if layanan_id in self._bukti or layanan_id in self._darurat:
            return None
        return (f"Bukti forensik belum diamankan. Gunakan {ISTILAH['tombol_isolasi']} (bukti diamankan "
                f"otomatis lebih dulu) atau {ISTILAH['tombol_darurat']} dengan alasan tertulis")

    def _alasan_bukti_pulih(self, layanan_id: str) -> str | None:
        rekam = self._bukti.get(layanan_id)
        if not rekam:
            if layanan_id in self._darurat:
                return ("Isolasi darurat dijalankan tanpa bukti: amankan bukti dulu, "
                        "pemulihan akan menghapus jejak penyerang")
            return "Bukti forensik belum diamankan: pemulihan akan menghapus jejak penyerang"
        cocok, pesan = self.rantai.periksa(rekam["nomor"])
        if not cocok:
            return f"Sidik jari bukti {rekam['nomor']} TIDAK COCOK ({pesan}): pemulihan dikunci"
        return None

    def amankan_bukti(self, layanan: dict, layanan_id: str, oleh: str, metode: str) -> dict:
        """Salin barang bukti + SHA-256 + berita acara. Melempar ValueError bila gagal / sudah ada."""
        l = layanan[layanan_id]
        ins = l["insiden"]
        if not ins:
            raise ValueError("Tidak ada insiden aktif di layanan ini")
        if layanan_id in self._bukti:
            raise ValueError(f"Bukti insiden ini sudah diamankan ({self._bukti[layanan_id]['nomor']})")
        sk = ins["skenario"]
        sudah_putus = any(ins["langkah_selesai"][i] for i in langkah_pemutus(sk))
        if ins.get("gangguan_bukti") and not sudah_putus:
            # Simulasi: server dibebani serangan sehingga agen forensik tidak merespons. Setelah jaringan
            # diputus (isolasi darurat), beban turun dan pengambilan bukti susulan berhasil.
            e = self.rantai.catat(oleh, BUKTI_GAGAL, {
                "insiden_id": ins.get("id"), "layanan": layanan_id, "skenario": sk,
                "sebab": "agen forensik tidak merespons (simulasi: server dibebani serangan)"})
            self._cermin(oleh, BUKTI_GAGAL, {"layanan": layanan_id, "hash_buku": e["hash"]})
            self.catat("kritis", f"✖ Pengambilan bukti di {l['nama']} GAGAL: agen forensik tidak merespons",
                       layanan=layanan_id, jenis="bukti")
            self.ubah()
            raise ValueError(f"Pengambilan bukti GAGAL: agen forensik tidak merespons. Gunakan "
                             f"{ISTILAH['tombol_darurat']} dengan alasan tertulis, lalu amankan bukti sesudahnya")
        susulan = layanan_id in self._darurat
        e = self.rantai.amankan(layanan_id=layanan_id, insiden_id=ins.get("id", layanan_id), skenario=sk,
                                petugas=oleh, metode=metode, susulan=susulan)
        d = e["detail"]
        rekam = {"nomor": d["nomor"], "sha256": d["sha256"], "hash_buku": e["hash"], "urutan_buku": e["urutan"],
                 "petugas": oleh, "metode": metode, "waktu": e["waktu"], "lokasi": d["lokasi"],
                 "detik": self._detik_insiden(layanan_id), "susulan": susulan,
                 "barang": [{k: b[k] for k in ("nama", "ket", "ukuran", "sha256")} for b in d["barang"]]}
        self._bukti[layanan_id] = rekam
        self._jejak_respons(layanan_id, bukti_detik=rekam["detik"], bukti_nomor=rekam["nomor"])
        ir = self._ir_insiden.get(layanan_id)
        self._cermin(oleh, BUKTI_DIAMANKAN, {"layanan": layanan_id, "nomor": d["nomor"], "sha256": d["sha256"],
                                            "hash_buku": e["hash"], "susulan": susulan,
                                            "adendum_untuk": ir["nomor"] if ir else None})
        self.catat("info", f"🔒 {ISTILAH['status_bukti_aman']} {d['nomor']} di {l['nama']}: {len(d['barang'])} berkas, "
                           f"SHA-256 {d['sha256'][:12]}… tercatat di {ISTILAH['buku_bukti']}"
                           + (" (susulan setelah isolasi darurat)" if susulan else ""),
                   layanan=layanan_id, jenis="bukti")
        if ir and not ir.get("bukti"):
            # Laporan sudah terbit lebih dulu (isolasi darurat): bukti menyusul sebagai adendum
            ir["bukti"] = self._ringkas_bukti(layanan_id)
            self.catat("info", f"Adendum {ir['nomor']}: bukti {d['nomor']} diamankan T+{rekam['detik']} dtk",
                       layanan=layanan_id, jenis="ir")
        self.catat_langkah(layanan, layanan_id, langkah_bukti(sk), True, metode, ISTILAH["langkah_bukti"], oleh)
        return rekam

    def _jadwalkan_pemutus(self, layanan: dict, layanan_id: str, sisa: list[dict], jeda_awal: float) -> None:
        mulai = self._jam() + jeda_awal
        for i, a in enumerate(sisa):
            self._antre_soar.append((mulai + JEDA_RUNBOOK * i, layanan_id, a["id"]))
        self._proses_antre_soar(layanan)          # yang sudah jatuh tempo langsung jalan

    def isolasi_darurat(self, layanan: dict, layanan_id: str, alasan: str, oleh: str) -> dict:
        """EMERGENCY OVERRIDE: putus jaringan TANPA menunggu bukti. Alasan wajib, dicatat permanen di
        buku rantai bukti + log audit, dan ikut di laporan ke manajemen."""
        self._proses_antre_soar(layanan)
        l = layanan[layanan_id]
        ins = l["insiden"]
        if not ins:
            raise ValueError("Tidak ada insiden aktif di layanan ini")
        if layanan_id in self._bukti:
            raise ValueError("Bukti sudah diamankan: gunakan isolasi standar. "
                             "Isolasi darurat hanya untuk saat bukti belum bisa diamankan")
        if layanan_id in self._darurat:
            raise ValueError("Isolasi darurat untuk insiden ini sudah dijalankan")
        alasan = " ".join(alasan.split())
        if len(alasan) < MIN_ALASAN_DARURAT:
            raise ValueError(f"Alasan isolasi darurat wajib diisi (minimal {MIN_ALASAN_DARURAT} karakter)")
        sk = ins["skenario"]
        antre = {a for _, lid, a in self._antre_soar if lid == layanan_id}
        sisa = [a for a in aksi_berjenis(sk, "pemutus") if not ins["langkah_selesai"][a["langkah"]] and a["id"] not in antre]
        if not sisa:
            raise ValueError("Semua tindakan pemutus untuk insiden ini sudah dijalankan")
        e = self.rantai.catat(oleh, ISOLASI_DARURAT, {
            "insiden_id": ins.get("id"), "layanan": layanan_id, "skenario": sk, "alasan": alasan,
            "status_bukti": "BELUM DIAMANKAN saat jaringan diputus", "tindakan": [a["id"] for a in sisa]})
        self._darurat[layanan_id] = {"alasan": alasan, "petugas": oleh, "waktu": e["waktu"], "hash_buku": e["hash"],
                                     "urutan_buku": e["urutan"], "detik": self._detik_insiden(layanan_id)}
        self._jejak_respons(layanan_id, darurat_detik=self._darurat[layanan_id]["detik"])
        self._cermin(oleh, ISOLASI_DARURAT, {"layanan": layanan_id, "alasan": alasan, "hash_buku": e["hash"]})
        self.catat("tinggi", f"⚠ {ISTILAH['tombol_darurat']} oleh {oleh} di {l['nama']}: bukti BELUM diamankan. "
                             f"Alasan: {alasan}", layanan=layanan_id, jenis="bukti")
        sudah_ada_ir = layanan_id in self._ir_insiden
        self._perintah_isolasi[layanan_id] = oleh
        self._jadwalkan_pemutus(layanan, layanan_id, sisa, 0.0)
        self.ubah()
        lahir = None if sudah_ada_ir else self._ir_insiden.get(layanan_id)
        return {"dijadwalkan": [a["id"] for a in sisa], "ir": lahir, "darurat": self._darurat[layanan_id],
                "ir_menunggu": layanan_id not in self._ir_insiden
                               and any(lid == layanan_id for _, lid, _a in self._antre_soar)}

    def verifikasi_untuk_pemulihan(self, layanan: dict, layanan_id: str, oleh: str) -> None:
        """Pencocokan PENUH (seluruh rantai buku + SHA-256 tiap berkas) tepat sebelum pemulihan.
        Hasilnya — cocok atau tidak — dicatat di buku rantai bukti. Tidak cocok = ValueError (409)."""
        rekam = self._bukti.get(layanan_id)
        if not rekam:
            raise ValueError(self._alasan_bukti_pulih(layanan_id))
        cocok, pesan = self.rantai.verifikasi_penuh(rekam["nomor"])
        ins = layanan[layanan_id]["insiden"]
        aksi = BUKTI_DIVERIFIKASI if cocok else VERIFIKASI_GAGAL
        e = self.rantai.catat(oleh, aksi, {"nomor": rekam["nomor"], "insiden_id": ins.get("id") if ins else None,
                                           "layanan": layanan_id, "sha256": rekam["sha256"], "cocok": cocok,
                                           "pesan": pesan, "keperluan": "pemulihan"})
        self._cermin(oleh, aksi, {"layanan": layanan_id, "nomor": rekam["nomor"], "cocok": cocok, "hash_buku": e["hash"]})
        self._jejak_respons(layanan_id, bukti_cocok=cocok)
        nama = layanan[layanan_id]["nama"]
        if not cocok:
            self.catat("kritis", f"✖ Verifikasi bukti {rekam['nomor']} GAGAL ({pesan}): pemulihan {nama} dikunci",
                       layanan=layanan_id, jenis="bukti")
            self.ubah()
            raise ValueError(f"Sidik jari bukti {rekam['nomor']} TIDAK COCOK ({pesan}). "
                             "Pemulihan dikunci; laporkan ke tim forensik")
        self.catat("info", f"✓ Bukti {rekam['nomor']} dicocokkan ulang sebelum pemulihan {nama}: {pesan}",
                   layanan=layanan_id, jenis="bukti")

    def tandai_manual(self, layanan: dict, layanan_id: str, indeks: int, selesai: bool, oleh: str) -> None:
        """Centang langkah oleh manusia — tunduk pada kunci urutan yang SAMA dengan tombol SOAR.
        IndexError = nomor langkah tidak ada; ValueError = urutan dilanggar (409)."""
        self._proses_antre_soar(layanan)
        ins = layanan[layanan_id]["insiden"]
        if not ins:
            raise ValueError("Tidak ada insiden aktif di layanan ini")
        if indeks >= len(ins["langkah"]):
            raise IndexError("Nomor langkah tidak ada")
        sk = ins["skenario"]
        if indeks == langkah_bukti(sk):
            if not selesai:
                raise ValueError(f"Bukti yang sudah diamankan tidak bisa dibatalkan: {ISTILAH['buku_bukti']} "
                                 "bersifat tambah-saja")
            self.amankan_bukti(layanan, layanan_id, oleh, "manual")   # centang = ambil bukti sungguhan
            return
        if selesai and indeks in langkah_pemutus(sk):
            alasan = self.alasan_tolak_pemutusan(layanan_id)
            if alasan:
                raise ValueError(alasan)
        if selesai and indeks in langkah_pemulihan(sk):
            alasan = self.syarat_pemulihan(layanan, layanan_id)
            if alasan:
                raise ValueError(alasan)
            self.verifikasi_untuk_pemulihan(layanan, layanan_id, oleh)
        self.catat_langkah(layanan, layanan_id, indeks, selesai, metode="manual", oleh=oleh)

    def _forensik(self, layanan: dict) -> dict:
        hasil = {}
        for lid, l in layanan.items():
            if not l["insiden"]:
                continue
            b = self._bukti.get(lid)
            if b:
                cocok, pesan = self.rantai.periksa(b["nomor"])
                b = {**b, "cocok": cocok, "periksa": pesan}
            hasil[lid] = {"bukti": b, "darurat": self._darurat.get(lid),
                          "gangguan": bool(l["insiden"].get("gangguan_bukti"))}
        return {"insiden": hasil, "buku": self.rantai.status_buku(), "min_alasan": MIN_ALASAN_DARURAT}

    def _jejak_respons(self, layanan_id: str, **nilai) -> None:
        if layanan_id in self._respons:
            self._respons[layanan_id].update(nilai)

    def respons(self, layanan: dict, layanan_id: str) -> dict:
        """Jejak respons insiden terakhir di satu layanan (detik sejak insiden dimulai), untuk nilai drill.
        Antrean SOAR yang sudah jatuh tempo diproses dulu supaya jejaknya terkini."""
        self._proses_antre_soar(layanan)
        return dict(self._respons.get(layanan_id, {}))

    def insiden_ditutup(self, layanan_id: str) -> None:
        self._jejak_respons(layanan_id, pulih_detik=self._detik_insiden(layanan_id))
        meta, b = self._meta_insiden.pop(layanan_id, None), self._bukti.get(layanan_id)
        if meta:
            self._riwayat_insiden.appendleft({**meta, "layanan_id": layanan_id, "selesai": _iso(),
                                              "petugas": b["petugas"] if b else None,
                                              "bukti": b["nomor"] if b else None})
        self._ir_insiden.pop(layanan_id, None)
        self._jejak.pop(layanan_id, None)
        self._perintah_isolasi.pop(layanan_id, None)
        self._bukti.pop(layanan_id, None)       # berita acara tetap abadi di buku rantai bukti
        self._darurat.pop(layanan_id, None)

    def _komando(self, layanan: dict) -> dict:
        return {lid: {"pic": PROFIL_LAYANAN[lid]["pic"],
                      "ir": self._ir_insiden.get(lid) if l["insiden"] else None,
                      "panggilan": self._panggilan.get(lid, [])[-3:][::-1]}
                for lid, l in layanan.items()}

    def perketat(self, layanan: dict, aset_id: str) -> None:
        """SOAR proaktif: pengerasan aset (tutup port dari luar, batasi alamat asal, pasang pembaruan).
        Tidak menunggu serangan — dipicu oleh PREDIKSI."""
        if aset_id in self._diperketat:
            raise ValueError("Aset ini sudah diperketat")
        s = INDEKS_SIMPUL[aset_id]
        sebelum = self._prediksi(layanan).get(aset_id, {}).get("persen")
        self._diperketat.add(aset_id)
        sesudah = self._prediksi(layanan).get(aset_id, {}).get("persen")
        rinci = f" — peluang serangan {sebelum}% → {sesudah}%" if sebelum is not None else ""
        self.catat("info", f"SOAR ▶ Pengerasan {s['nama']} {s['ip']}:{s['port']}: akses diperketat, "
                           f"paparan turun {round((1 - FAKTOR_PERKETAT) * 100)}%{rinci}", jenis="soar")
        self.ubah()

    # ======================================================================
    # MESIN DETEKSI ATURAN: peristiwa mentah sintetis → temuan (app/deteksi.py)
    # ======================================================================
    def latihan_deteksi(self, layanan: dict, jenis: str, aset_id: str | None = None) -> dict:
        """Latihan: putar rangkaian PERISTIWA MENTAH sintetis (upaya login / koneksi). Temuan lahir dari aturan
        di app/deteksi.py saat peristiwa itu tiba, bukan dari baris log yang disuntikkan."""
        if jenis not in JENIS_LATIHAN:
            raise ValueError("Jenis latihan deteksi tidak dikenal")
        if jenis == "akses_ot":
            if aset_id not in (None, ASET_LATIHAN_OT):
                raise ValueError("Latihan akses OT hanya untuk pengendali genset")
            aset_id = ASET_LATIHAN_OT
        aset_id = aset_id or "ssh"
        if aset_id not in INDEKS_SIMPUL or not INDEKS_SIMPUL[aset_id]["port"]:
            raise ValueError("Aset tidak dikenal")
        dmz = [s for s in SIMPUL if s["zona"] == "dmz"]
        rangkaian = rangkaian_latihan(jenis, INDEKS_SIMPUL[aset_id], dmz)
        t0 = self._jam()
        self._antre_det += [(t0 + dt, ev) for dt, ev in rangkaian]
        self._antre_det.sort(key=lambda x: x[0])
        s = INDEKS_SIMPUL[aset_id]
        sasaran = (f"{s['nama']} {s['ip']}:{s['port']}" if jenis != "pindai_port"
                   else "aset DMZ " + ", ".join(f"{d['ip']}" for d in dmz))
        judul = ("akses tanpa izin ke zona kendali OT" if jenis == "akses_ot"
                 else ATURAN_DETEKSI[jenis]["nama"].lower())
        self.catat("info", f"Latihan deteksi: {len(rangkaian)} peristiwa mentah ({judul}) "
                           f"diputar ke {sasaran} selama ≈{round(rangkaian[-1][0])} dtk (data sintetis)", jenis="deteksi")
        self._proses_deteksi()
        self.ubah()
        return {"jenis": jenis, "aset_id": aset_id, "peristiwa": len(rangkaian),
                "durasi_detik": round(rangkaian[-1][0], 1)}

    def impor_log(self, layanan: dict, nama: str, isi: str, aset_ssh: str = "ssh", terurai: tuple | None = None) -> dict:
        """Log ASLI dari Operator → peristiwa mentah → aturan yang sama dengan latihan. Waktu diputar ulang relatif:
        peristiwa terakhir di log = saat ini, jarak antarperistiwa tetap. Temuan hanya menaikkan WASPADA.
        terurai = hasil urai_log() yang sudah dikerjakan pemanggil DI LUAR kunci keadaan (berkas besar tidak boleh
        menahan dasbor semua layar); bila None, diurai di sini (dipakai drill: log ceritanya pendek)."""
        if aset_ssh not in INDEKS_SIMPUL or not INDEKS_SIMPUL[aset_ssh]["port"]:
            raise ValueError("Aset tidak dikenal")
        peristiwa, ringkasan = terurai or baca_log(isi, SIMPUL, aset_ssh)
        sekarang, akhir = self._jam(), peristiwa[-1][0]
        baru = []
        for t, ev in peristiwa:
            for tm in self.deteksi.proses(ev, sekarang - (akhir - t)):
                tm.asal, tm.berkas = "impor", nama
                baru.append(tm)
                aset = ", ".join(INDEKS_SIMPUL[a]["nama"] for a in tm.aset) or "tanpa port terbuka"
                attck = ringkas_mitre(tm.aturan)
                self.catat(tm.keparahan, f"Deteksi ▶ {tm.nama} ({tm.id}) ke {aset} dari {tm.sumber} — {tm.alasan()} "
                                         f"(log impor {nama})" + (f" [ATT&CK {attck}]" if attck else ""), jenis="deteksi")
        prediksi = self._prediksi(layanan)
        naik = sorted({a for tm in baru for a in tm.aset if prediksi.get(a, {}).get("proaktif")})
        self.catat("info", f"Impor log «{nama}»: {ringkasan['dikenali']} dari {ringkasan['baris']} baris dikenali "
                           f"({ringkasan['format']}) → {len(baru)} temuan", jenis="deteksi")
        self.ubah()
        return {**ringkasan, "berkas": nama,
                "temuan": [{"id": tm.id, "aturan": tm.aturan, "nama": tm.nama, "keparahan": tm.keparahan,
                            "sumber": tm.sumber, "aset": tm.aset, "alasan": tm.alasan(), "mitre": teknik_mitre(tm.aturan)}
                           for tm in baru],
                "waspada": [INDEKS_SIMPUL[a]["nama"] for a in naik]}

    @staticmethod
    def urai_log(isi: str, aset_ssh: str = "ssh") -> tuple:
        """Urai berkas log tanpa menyentuh keadaan Menara: aman dipanggil tanpa memegang kunci keadaan."""
        if aset_ssh not in INDEKS_SIMPUL or not INDEKS_SIMPUL[aset_ssh]["port"]:
            raise ValueError("Aset tidak dikenal")
        return baca_log(isi, SIMPUL, aset_ssh)

    def _proses_deteksi(self) -> None:
        sekarang = self._jam()
        siap = [x for x in self._antre_det if x[0] <= sekarang]
        if not siap:
            return
        self._antre_det = [x for x in self._antre_det if x[0] > sekarang]
        for t, ev in siap:
            for tm in self.deteksi.proses(ev, t):
                aset = ", ".join(f"{INDEKS_SIMPUL[a]['nama']} {INDEKS_SIMPUL[a]['ip']}:{INDEKS_SIMPUL[a]['port']}"
                                 for a in tm.aset) or "tidak ada port terbuka"
                attck = ringkas_mitre(tm.aturan)
                self.catat(tm.keparahan, f"Deteksi ▶ {tm.nama} ({tm.id}) ke {aset} dari {tm.sumber} — {tm.alasan()}"
                                         + (f" [ATT&CK {attck}]" if attck else ""), jenis="deteksi")
        self.ubah()

    def _deteksi_tampil(self, prediksi: dict) -> dict:
        sekarang = self._jam()
        temuan = [{"id": tm.id, "aturan": tm.aturan, "nama": tm.nama, "keparahan": tm.keparahan, "sumber": tm.sumber,
                   "aset": tm.aset, "jumlah": tm.jumlah, "alasan": tm.alasan(), "aktif": tm.aktif(sekarang),
                   "waktu": self._iso_mono(tm.mulai), "mitre": teknik_mitre(tm.aturan)}
                  for tm in self.deteksi.temuan[-10:]]
        return {"aturan": {k: {x: v[x] for x in ("nama", "ambang", "jendela", "keparahan", "peluang") if x in v}
                           for k, v in ATURAN_DETEKSI.items()},
                "temuan": temuan[::-1], "menunggu": len(self._antre_det)}

    def _iso_mono(self, t: float) -> str:
        """Waktu monotonic (jam internal) → ISO-8601 UTC, untuk ditampilkan."""
        return (datetime.now(timezone.utc) - timedelta(seconds=max(0.0, self._jam() - t))).isoformat(timespec="seconds")

    def _peringatan(self, layanan: dict, prediksi: dict) -> list[dict]:
        """Daftar peringatan terbaru untuk dasbor. Setiap label diambil dari data yang sebenarnya:
        siapa Operator yang mengisolasi, nomor berita acara bukti, aturan deteksi yang terpenuhi."""
        sekarang, hasil = self._jam(), []
        ditutup = {x for t in self._ditutup.values() for x in t.get("deteksi", ())}
        dalam_insiden = set(self._status_insiden(layanan))
        for tm in self.deteksi.temuan[-10:]:
            terangkat = [a for a in tm.aset if prediksi.get(a, {}).get("proaktif") and tm.id in prediksi[a]["sumber"]]
            if not tm.aktif(sekarang):
                status, kelas = "Berakhir", "selesai"
            elif tm.id in ditutup:
                status, kelas = "Ditutup lewat triase", "selesai"
            elif tm.aset and all(a in dalam_insiden for a in tm.aset):
                status, kelas = "Aset ditangani lewat playbook insiden", "ditahan"
            elif terangkat:
                status, kelas = "Aset dinaikkan ke WASPADA", "terbuka"
            else:
                status, kelas = "Dipantau", "pantau"
            sasaran = ", ".join(INDEKS_SIMPUL[a]["nama"] for a in tm.aset) or "tanpa port terbuka"
            hasil.append({"id": tm.id, "jenis": "deteksi", "aturan": tm.aturan, "judul": f"{tm.nama} · {sasaran}",
                          "rincian": tm.alasan(), "keparahan": tm.keparahan, "waktu": self._iso_mono(tm.mulai),
                          "status": status, "kelas": kelas, "mitre": teknik_mitre(tm.aturan),
                          "sumber_data": (SUMBER_DATA["impor"].format(berkas=tm.berkas) if tm.asal == "impor"
                                          else SUMBER_DATA["deteksi"])})
        for aid in sorted(self._tanda_ai):
            if aid in self._ai_sejak and aid in prediksi and prediksi[aid].get("ai"):
                s = INDEKS_SIMPUL[aid]
                hasil.append({"id": f"ai-{aid}", "jenis": "ai", "judul": f"Lalu lintas tidak wajar (AI lokal) · {s['nama']}",
                              "rincian": prediksi[aid]["ai"]["alasan"], "keparahan": "sedang",
                              "waktu": self._iso_mono(self._ai_sejak[aid]),
                              "status": "Aset dinaikkan ke WASPADA" if prediksi[aid]["proaktif"] else "Dipantau",
                              "kelas": "terbuka" if prediksi[aid]["proaktif"] else "pantau",
                              "mitre": [], "sumber_data": SUMBER_DATA["ai"]})
        for lid, meta in self._meta_insiden.items():
            if not layanan.get(lid, {}).get("insiden"):
                continue
            b, dr = self._bukti.get(lid), self._darurat.get(lid)
            if lid in self._ir_insiden:
                if dr:
                    status = (f"Diisolasi darurat oleh {dr['petugas']} · "
                              + (f"bukti susulan {b['nomor']}" if b else "bukti belum diamankan"))
                else:
                    status = f"Diisolasi oleh {b['petugas']} · bukti {b['nomor']}" if b else "Terisolasi"
                kelas = "ditahan"
            elif b:
                status, kelas = f"Bukti {b['nomor']} aman · isolasi berjalan", "terbuka"
            else:
                status, kelas = "Menunggu keputusan Operator", "terbuka"
            hasil.append({"id": f"ins-{lid}", "jenis": "insiden", "judul": f"{meta['judul']} · {meta['nama']}",
                          "rincian": None, "keparahan": "kritis", "waktu": meta["mulai"], "status": status,
                          "kelas": kelas, "layanan_id": lid, "mitre": teknik_mitre(meta["skenario"]),
                          "sumber_data": SUMBER_DATA["insiden"]})
        for r in self._riwayat_insiden:
            status = (f"Diisolasi oleh {r['petugas']} · bukti {r['bukti']} · dipulihkan" if r["bukti"]
                      else "Dipulihkan")
            hasil.append({"id": f"pulih-{r['layanan_id']}-{r['selesai']}", "jenis": "pulih",
                          "judul": f"{r['judul']} · {r['nama']}", "rincian": None, "keparahan": "info",
                          "waktu": r["selesai"], "status": status, "kelas": "selesai",
                          "mitre": teknik_mitre(r.get("skenario")), "sumber_data": SUMBER_DATA["insiden"]})
        hasil.sort(key=lambda x: x["waktu"], reverse=True)
        return hasil[:MAKS_PERINGATAN]

    def rincian_lapsit(self, layanan: dict) -> dict:
        """Bahan LAPSIT formal yang diambil dari keadaan SEBENARNYA (bukan teks tetap):
        - per insiden aktif: jejak tiap langkah playbook (kapan, oleh siapa, T+detik), bukti, laporan, MTTC, darurat;
        - tabel indikator kompromi (IoC): alamat ancaman skenario (diblokir hanya bila langkah pemutusnya sudah
          berjalan) dan sumber temuan mesin deteksi aturan (tidak pernah diblokir otomatis: dua kunci)."""
        self._proses_antre_soar(layanan)
        self._proses_deteksi()
        insiden = {}
        for lid, l in layanan.items():
            ins = l.get("insiden")
            if not ins:
                continue
            jejak = self._jejak.get(lid, {})
            antre = {a["langkah"] for _, x, aid in self._antre_soar if x == lid
                     for a in SOAR[ins["skenario"]] if a["id"] == aid}
            insiden[lid] = {
                "langkah": [{"teks": teks, "selesai": ins["langkah_selesai"][i], "antre": i in antre, **jejak.get(i, {})}
                            for i, teks in enumerate(ins["langkah"])],
                "bukti": self._bukti.get(lid), "ir": self._ir_insiden.get(lid), "darurat": self._darurat.get(lid),
                "mttc": (self._mttc.get(lid) or {}).get("detik"), "jeda_runbook": JEDA_RUNBOOK}
        ioc, indeks = [], {}

        def tambah(tipe, nilai, rujukan, konteks, status):
            """Satu baris per nilai: temuan berbeda atas nilai yang sama digabung rujukan dan asetnya."""
            if nilai in indeks:
                x = indeks[nilai]
                x["rujukan"] += [] if rujukan in x["rujukan"] else [rujukan]
                x["konteks"] += [] if konteks in x["konteks"] else [konteks]
                return
            indeks[nilai] = {"tipe": tipe, "nilai": nilai, "rujukan": [rujukan], "konteks": [konteks], "status": status}
            ioc.append(indeks[nilai])

        for lid, l in layanan.items():
            ins = l.get("insiden")
            if not ins:
                continue
            langkah = DAMPAK[ins["skenario"]].get("langkah", {})
            putus = next((i for i, e in langkah.items() if e.get("ancaman") == "isolasi"), None)
            diblokir = putus is not None and ins["langkah_selesai"][putus]
            for a in DAMPAK[ins["skenario"]].get("ancaman", []):
                tambah(f"Alamat IP · {a['nama']}", f"{a['ip']}:{a['port']}", a["ioc"], l["nama"],
                       "Diblokir di firewall (simulasi)" if diblokir else "Aktif · belum diblokir")
        status_det = {x["id"]: x["status"] for x in self._peringatan(layanan, self._prediksi(layanan))
                      if x["jenis"] == "deteksi"}
        sekarang = self._jam()
        for tm in self.deteksi.temuan[-10:]:
            if not tm.aktif(sekarang):
                continue
            status = status_det.get(tm.id, "Dipantau")
            status = status if "playbook" in status else f"{status} · tidak diblokir otomatis"
            sasaran = ", ".join(INDEKS_SIMPUL[a]["nama"] for a in tm.aset) or "—"
            tambah("Alamat IP sumber (temuan aturan deteksi)", tm.sumber, tm.id, sasaran, status)
            if "fungsi" in tm.rincian:
                for a in tm.aset:
                    s = INDEKS_SIMPUL[a]
                    tambah("Parameter Modbus (perintah tulis)",
                           f"Fungsi {tm.rincian['fungsi']:02d} · {NAMA_FUNGSI_MODBUS.get(tm.rincian['fungsi'], 'tulis')} "
                           f"ke {s['ip']}:{s['port']}, pukul {tm.rincian['jam']:02d}.00", tm.id, s["nama"], status)
        for x in ioc:
            x["rujukan"], x["konteks"] = ", ".join(x["rujukan"]), ", ".join(x["konteks"])
        return {"insiden": insiden, "ioc": ioc}

    def peringatan_lapsit(self, layanan: dict) -> list[dict]:
        """Daftar peringatan terbaru (dengan teknik MITRE ATT&CK dan sumber data) untuk LAPSIT PDF.
        Peristiwa deteksi yang sudah jatuh tempo diproses dulu, agar laporan tidak tertinggal dari layar."""
        self._proses_deteksi()
        return self._peringatan(layanan, self._prediksi(layanan))

    # ======================================================================
    # TRIASE PERINGATAN dan NILAI KESIAPAN SIBER
    # ======================================================================
    def tutup_peringatan(self, layanan: dict, aset_id: str, status: str, alasan: str, oleh: str) -> dict:
        """Operator menutup peringatan WASPADA beralasan. Tidak ada yang dihapus: penutupan menjadi halaman
        baru di buku rantai bukti, dan bukti baru membuka peringatan lagi."""
        if status not in STATUS_TUTUP:
            raise ValueError("Status penutupan tidak dikenal")
        alasan = " ".join(alasan.split())
        if len(alasan) < MIN_ALASAN_TUTUP:
            raise ValueError(f"Alasan penutupan wajib diisi (minimal {MIN_ALASAN_TUTUP} karakter)")
        self._periksa_ai(layanan)                 # pastikan episode anomali AI sudah tercatat waktunya
        if aset_id in self._status_insiden(layanan):
            raise ValueError("Aset ini sedang dalam insiden aktif: tangani lewat playbook, bukan ditutup sebagai peringatan")
        pr = self._prediksi(layanan).get(aset_id)
        if not pr or not pr["proaktif"]:
            raise ValueError("Tidak ada peringatan WASPADA terbuka di aset ini")
        tutup = self._ditutup.setdefault(aset_id, {"berita": set(), "ai_sejak": None, "deteksi": set()})
        tutup.setdefault("deteksi", set())
        tutup["berita"] |= {x for x in pr["sumber"] if x != SUMBER_AI and not x.startswith(AWALAN_DET)}
        tutup["deteksi"] |= {x for x in pr["sumber"] if x.startswith(AWALAN_DET)}
        if SUMBER_AI in pr["sumber"]:
            tutup["ai_sejak"] = self._ai_sejak.get(aset_id)
        s, label = INDEKS_SIMPUL[aset_id], ISTILAH[STATUS_TUTUP[status]]
        e = self.rantai.catat(oleh, PERINGATAN_DITUTUP, {
            "aset": aset_id, "nama": s["nama"], "alamat": f"{s['ip']}:{s['port']}", "status": status, "label": label,
            "sumber": pr["sumber"], "peluang_persen": pr["persen"], "alasan": alasan})
        self._cermin(oleh, PERINGATAN_DITUTUP, {"aset": aset_id, "status": status, "alasan": alasan, "hash_buku": e["hash"]})
        self._hitung_tutup[status] += 1
        catatan = {"aset": aset_id, "nama": s["nama"], "status": status, "label": label, "alasan": alasan,
                   "oleh": oleh, "waktu": e["waktu"], "peluang_persen": pr["persen"], "sumber": pr["sumber"],
                   "hash_buku": e["hash"]}
        self._riwayat_tutup.appendleft(catatan)
        self.catat("info", f"Triase ▶ peringatan WASPADA {s['nama']} {s['ip']}:{s['port']} ditutup sebagai {label} "
                           f"oleh {oleh} (peluang {pr['persen']}%, sumber {', '.join(pr['sumber'])}). Alasan: {alasan}. "
                           f"Tercatat di {ISTILAH['buku_bukti']}; bukti baru akan membuka peringatan lagi.", jenis="bukti")
        self.ubah()
        return catatan

    def _rapikan_tutup(self) -> None:
        """Buang catatan penutupan yang sudah tidak berlaku (berita kedaluwarsa, episode AI berakhir)."""
        aktif = {b["id"] for b in self.osint.aktif}
        temuan_aktif = {tm.id for tm in self.deteksi.aktif(self._jam())}
        for aid in list(self._ditutup):
            t = self._ditutup[aid]
            t["berita"] &= aktif
            t["deteksi"] = t.get("deteksi", set()) & temuan_aktif
            if t["ai_sejak"] is not None and t["ai_sejak"] != self._ai_sejak.get(aid):
                t["ai_sejak"] = None
            if not t["berita"] and t["ai_sejak"] is None and not t["deteksi"]:
                del self._ditutup[aid]

    def _kesiapan(self, layanan: dict, prediksi: dict) -> dict:
        """Nilai kesiapan siber: dua sub-skor (Kerawanan, Insiden) per layanan, lalu nilai posko."""
        per, total_k, total_i, total_n, belum_ditahan = [], 0.0, 0.0, 0, False
        for lid, l in layanan.items():
            aset = [a for a, pemilik in PEMILIK_SIMPUL.items() if pemilik == lid]
            n = len(aset) or 1
            rata = sum(prediksi.get(a, {}).get("prob", 0.0) for a in aset) / n
            temuan = sum(1 for a in aset if INDEKS_SIMPUL[a].get("status") == "waspada" and a not in self._diperketat)
            backup = l["jam_sejak_backup"] > BATAS_JAM_BACKUP or not l["backup_teruji"]
            k = 100 - BOBOT_KERAWANAN["peluang"] * rata - BOBOT_KERAWANAN["temuan"] * temuan / n \
                - BOBOT_KERAWANAN["backup"] * backup
            potong, ins = 0, l["insiden"]
            if ins:
                ditahan = ins["langkah_selesai"][TAHAP_PENAHANAN[ins["skenario"]]]
                potong += POTONG_INSIDEN["ditahan" if ditahan else "aktif"]
                belum_ditahan |= not ditahan
            terbuka = sum(1 for a in aset if prediksi.get(a, {}).get("proaktif"))
            potong += min(POTONG_INSIDEN["maks_peringatan"], POTONG_INSIDEN["peringatan"] * terbuka)
            i = 100 - potong
            nilai = min(k, i)
            per.append({"id": lid, "singkat": l.get("singkat", l["nama"]), "aset": len(aset),
                        "kerawanan": round(k), "insiden": round(i), "nilai": round(nilai), "huruf": huruf_nilai(nilai),
                        "rincian": {"peluang_rata": round(rata * 100), "temuan": temuan, "backup_bermasalah": backup,
                                    "peringatan_terbuka": terbuka, "insiden": bool(ins)}})
            total_k += k * len(aset); total_i += i * len(aset); total_n += len(aset)
        k_pos, i_pos = total_k / total_n, total_i / total_n
        nilai = min(k_pos, i_pos)
        batas = None
        if belum_ditahan and nilai > PLAFON_INSIDEN_AKTIF:
            nilai, batas = PLAFON_INSIDEN_AKTIF, "Ada insiden yang belum ditahan: nilai posko paling tinggi D"
        return {"nilai": round(nilai), "huruf": huruf_nilai(nilai), "kerawanan": round(k_pos), "insiden": round(i_pos),
                "batas": batas, "per_layanan": per,
                "triase": {"jumlah": dict(self._hitung_tutup), "riwayat": list(self._riwayat_tutup),
                           "min_alasan": MIN_ALASAN_TUTUP}}

    # ======================================================================
    # MESIN WAKTU
    # ======================================================================
    def maju(self, layanan: dict) -> None:
        sekarang = self._jam()
        n = int(sekarang - self._detak_terakhir)
        if n > 0:
            self._detak_terakhir += n
            p = self._parameter(layanan)
            ada_insiden = any(l["insiden"] for l in layanan.values())
            for _ in range(min(n, PANJANG_RIWAYAT)):
                v = self.beban + (p["target"] - self.beban) * 0.3 + self._acak.uniform(-1, 1) * p["goyang"]
                if p["lonjakan"] and self._acak.random() < p["lonjakan"]:
                    v += 14
                self.beban = max(2.0, min(100.0, v))
                self.riwayat.append(round(self.beban, 1))
                self._tampung(round(self.beban, 1), ada_insiden)
        siap = [e for t, e in self._antre if t <= sekarang]
        self._antre = [(t, e) for t, e in self._antre if t > sekarang]
        for e in siap:
            self._peristiwa.append(self._entri(e["tingkat"], e["pesan"], e["rel_menit"], e["layanan"]))
        self._proses_antre_soar(layanan)
        self._periksa_ai(layanan)                     # AI lokal: catat perubahan penilaian
        self._proses_deteksi()                        # mesin deteksi aturan: peristiwa mentah → temuan
        # Radio satpam
        baru, habis = self.osint.detak()
        for a in habis:
            self.catat("info", f"CTI {a['id']} kedaluwarsa: berita tidak lagi dianggap segar", jenis="cti")
        for b in baru:
            self._umumkan(b, layanan)
        if baru or habis:
            self.ubah()
        self._rapikan_tutup()                         # triase: buang penutupan yang sudah tidak berlaku
        # Bila daftar aset "waspada proaktif" berubah (berita memudar), minta gambar ulang peta
        tanda = tuple(sorted(k for k, v in self._prediksi(layanan).items() if v["proaktif"]))
        if tanda != self._tanda_cti:
            self._tanda_cti = tanda
            self.ubah()
        if sekarang >= self._info_berikut:
            self._info_berikut = sekarang + JEDA_INFO_RUTIN
            if not any(l["insiden"] for l in layanan.values()):
                self.catat("info", self._acak.choice(INFO_RUTIN))

    # ======================================================================
    # MENURUNKAN STATUS
    # ======================================================================
    def _turunkan(self, layanan: dict, prediksi: dict) -> tuple[dict, list[dict], int, list[str]]:
        status = {s["id"]: (s.get("status", "normal"), s.get("catatan", "Normal")) for s in SIMPUL}
        self._sebab = {}                              # v5: simpul → layanan yang insidennya memengaruhi
        ancaman: dict[str, dict] = {}
        kerumunan, asal_kerumunan = 0, []
        for lid, l in layanan.items():
            ins = l["insiden"]
            if not ins:
                continue
            d = DAMPAK[ins["skenario"]]
            peta = dict(d["perangkat"])
            status_ancaman, jml_kerumunan = "kritis", d["kerumunan"]
            for i, beres in enumerate(ins["langkah_selesai"]):
                if not beres:
                    continue
                efek = d["langkah"].get(i, {})
                peta.update(efek.get("perangkat", {}))
                status_ancaman = efek.get("ancaman", status_ancaman)
                jml_kerumunan = efek.get("kerumunan", jml_kerumunan)
            for pid, (st, cat) in peta.items():
                if PERINGKAT[st] > PERINGKAT[status[pid][0]]:
                    status[pid] = (st, f"{cat} · {l['nama']}")
                    self._sebab[pid] = lid
            for a in d["ancaman"]:
                lama = ancaman.get(a["ip"])
                if not lama or PERINGKAT[status_ancaman] > PERINGKAT[lama["status"]]:
                    ancaman[a["ip"]] = {**a, "status": status_ancaman, "layanan": lid}
            if jml_kerumunan > kerumunan:
                kerumunan, asal_kerumunan = jml_kerumunan, d.get("asal_kerumunan", [])
        # KORELASI PROAKTIF: aset yang masih normal, tetapi diprediksi akan diserang → waspada
        for aid, pr in prediksi.items():
            if pr["proaktif"] and status[aid][0] == "normal":
                status[aid] = ("waspada", f"Waspada proaktif ({', '.join(pr['sumber'])}): "
                                          f"peluang serangan {pr['persen']}%")
        return status, list(ancaman.values()), kerumunan, asal_kerumunan

    # ======================================================================
    # HIDANGAN UNTUK BROWSER
    # ======================================================================
    def _benih_linimasa(self) -> list[dict]:
        """60 menit DATA LATIHAN sebelum posko dibuka: beban dasar + goyang acak berbenih tetap.
        Sengaja tanpa insiden dan tanpa anomali AI: pita hanya lahir dari kejadian di sesi ini."""
        acak, akhir, v = random.Random(BENIH_LINIMASA), datetime.now(timezone.utc), BEBAN_DASAR["target"]
        hasil = []
        for i in range(MENIT_LINIMASA, 0, -1):
            v = max(5.0, min(55.0, v + (BEBAN_DASAR["target"] - v) * 0.3 + acak.uniform(-1, 1) * BEBAN_DASAR["goyang"]))
            hasil.append({"akhir": (akhir - timedelta(minutes=i - 1)).isoformat(timespec="seconds"),
                          "rata": round(v, 1), "puncak": round(min(100.0, v + acak.uniform(2, 8)), 1),
                          "asal": "latihan", "insiden": False, "ai": {}})
        return hasil

    def _tampung(self, v: float, ada_insiden: bool) -> None:
        """Satu detik beban masuk keranjang menit berjalan; 60 detik menjadi satu titik linimasa."""
        self._ember.append(v)
        self._ember_insiden |= ada_insiden
        if len(self._ember) < 60:
            return
        self._linimasa.append({"akhir": _iso(), "rata": round(sum(self._ember) / len(self._ember), 1),
                               "puncak": max(self._ember), "asal": "posko",
                               "insiden": self._ember_insiden, "ai": dict(self._ember_ai)})
        self._ember, self._ember_insiden = [], False
        self._ember_ai = {a: r for a, r in self._ember_ai.items() if a in self._tanda_ai}   # yang masih berlangsung

    def _linimasa_tampil(self) -> dict:
        """Linimasa 60 menit + pita anomali AI per aset. Isinya berubah sekali per menit atau saat penilaian AI
        berubah, sehingga siaran ralat hanya mengirimnya bila memang ada yang baru."""
        menit = list(self._linimasa)
        slot = [m["ai"] for m in menit] + [self._ember_ai]       # indeks terakhir = menit berjalan
        pita, buka = [], {}
        for i, ai in enumerate(slot + [{}]):
            for aid in [a for a in buka if a not in ai]:
                i0 = buka.pop(aid)
                pita.append({"aset": aid, "nama": INDEKS_SIMPUL[aid]["nama"], "alasan": slot[i - 1][aid],
                             "dari": i0, "sampai": i - 1,
                             "berlangsung": i - 1 == len(slot) - 1 and aid in self._tanda_ai})
            for aid in ai:
                buka.setdefault(aid, i)
        return {"menit": menit, "pita": sorted(pita, key=lambda x: (x["dari"], x["aset"])),
                "ambang": AMBANG, "posko_sejak": self._posko_sejak}

    def _lalu_lintas(self) -> dict:
        v = self.beban
        zona = "kritis" if v >= AMBANG["kritis"] else "waspada" if v >= AMBANG["waspada"] else "aman"
        riwayat = list(self.riwayat)
        return {"beban": round(v, 1), "zona": zona, "mbps": round(v * 10),
                "pps": round(v * 812), "puncak": round(max(riwayat or [v])),
                "riwayat": riwayat, "ambang": AMBANG,
                "berjalan": {"rata": round(sum(self._ember) / len(self._ember), 1) if self._ember else round(v, 1),
                             "detik": len(self._ember)}}

    def _postur(self, tampil, status, ancaman, lalu_lintas, prediksi) -> tuple[dict, dict]:
        warna = [l["status"] for l in tampil]
        sehat = warna.count("hijau")
        patuh = sum(1 for l in tampil if l["jam_sejak_backup"] <= BATAS_JAM_BACKUP and l["backup_teruji"])
        anomali = sum(1 for s in SIMPUL if s.get("port") and status[s["id"]][0] in ("waspada", "kritis"))
        anomali += sum(1 for a in ancaman if a["status"] == "kritis")
        insiden = [l for l in tampil if l["insiden"]]
        if "merah" in warna or lalu_lintas["zona"] == "kritis":
            tingkat = "kritis"
        elif "kuning" in warna or lalu_lintas["zona"] == "waspada" or anomali:
            tingkat = "waspada"
        else:
            tingkat = "aman"
        # v5.1: ringkasan singkat — fragmen, bukan paragraf
        if insiden:
            ringkas = f"{len(insiden)} insiden · {', '.join(l.get('singkat', l['nama']) for l in insiden)} · " \
                      f"beban {lalu_lintas['beban']:.0f}%"
        else:
            ringkas = f"Siaga · {anomali} catatan · beban {lalu_lintas['beban']:.0f}%"
        puncak = max(prediksi.values(), key=lambda x: x["prob"], default=None)
        if puncak:
            ringkas += f" · {'AI' if puncak['sumber'] == [SUMBER_AI] else 'CTI'} {puncak['nama']} {puncak['persen']}%"
        kpi = {"layanan_sehat": sehat, "layanan_total": len(warna),
               "host_terpantau": len(ASET_BERPORT), "anomali": anomali,
               "backup_patuh": patuh, "insiden_aktif": len(insiden),
               "cti_aktif": len(self.osint.aktif),
               "risiko_tertinggi": puncak["persen"] if puncak else 0,
               "insiden_sejak": self._jumlah_insiden, "posko_sejak": self._posko_sejak,
               "mttc_rata": round(sum(self._mttc_semua) / len(self._mttc_semua)) if self._mttc_semua else None,
               "mttc_n": len(self._mttc_semua)}
        return {"tingkat": tingkat, "ringkasan": ringkas}, kpi

    def _cti(self, prediksi: dict, lengkap: bool) -> dict:
        sekarang = self._jam()
        berita = [{"id": a["id"], "sumber": a["sumber"], "judul": a["judul"], "port": a["port"],
                   "sektor": a["sektor"], "keyakinan": a["keyakinan"], "saran": a["saran"],
                   "terbit": a["terbit"], "korelasi": a.get("korelasi", []),
                   "kesegaran": round(self.osint.kesegaran(a), 2),
                   "sisa_detik": max(0, round(a["habis_mono"] - sekarang))} for a in self.osint.aktif]
        hasil = {"prediksi": sorted(prediksi.values(), key=lambda x: -x["prob"]), "berita": berita,
                 "berikut_detik": max(0, round(self.osint.berikut - sekarang)),
                 "ambang_proaktif": AMBANG_PROAKTIF,
                 "ai": {**DETEKTOR.ringkasan(), "aset_anomali": len(self._tanda_ai)}}
        if lengkap:
            hasil["riwayat"] = list(self.osint.riwayat)
        return hasil

    def _soar(self, layanan: dict) -> dict:
        antre: dict[str, list[str]] = {}
        for _, lid, aid in self._antre_soar:
            antre.setdefault(lid, []).append(aid)
        # F-04: browser tahu kapan PULIHKAN boleh dibuka, dan alasannya bila belum
        syarat = {lid: self.syarat_pemulihan(layanan, lid) for lid, l in layanan.items() if l["insiden"]}
        return {"katalog": SOAR, "antre": antre, "mttc": self._mttc, "penahanan": TAHAP_PENAHANAN,
                "syarat_pulih": syarat}

    def _peta(self, status: dict, ancaman: list[dict], kerumunan: int, asal_kerumunan: list[str]) -> dict:
        """Pandangan MAKRO: dari mana ancaman datang dan seberapa keras ia menghantam markas.
        Dibangun dari data yang SAMA dengan topologi (status, ancaman, berita CTI), sehingga
        peta global dan denah internal mustahil saling bertentangan."""
        def wilayah(kode: str) -> dict:
            return {"id": kode, **WILAYAH[kode]}

        serangan = []
        for a in ancaman:                                   # insiden aktif: ancaman nyata (simulasi)
            serangan.append({"id": f"ins-{a['ip']}", "jenis": "insiden", "asal": wilayah(a["asal"]),
                             "status": "diblokir" if a["status"] == "isolasi" else "kritis",
                             "label": f"{a['nama']} {a['ip']} ({a['ioc']})", "intensitas": 3})
        if kerumunan:                                       # botnet: makin banyak sumber, makin banyak garis
            jumlah = min(len(asal_kerumunan), max(1, round(kerumunan / 3)))
            for kode in asal_kerumunan[:jumlah]:
                serangan.append({"id": f"bot-{kode}", "jenis": "insiden", "asal": wilayah(kode),
                                 "status": "kritis" if kerumunan >= 10 else "waspada",
                                 "label": f"Sumber banjir trafik · {WILAYAH[kode]['nama']}", "intensitas": 2})
        for b in self.osint.aktif:                          # intelijen: peringatan dini, belum serangan
            kuat = any(k["persen"] >= AMBANG_PROAKTIF * 100 for k in b.get("korelasi", []))
            serangan.append({"id": f"cti-{b['id']}", "jenis": "cti", "asal": wilayah(b["asal"]),
                             "status": "waspada" if kuat else ("pantau" if b.get("korelasi") else "abaikan"),
                             "label": f"{b['id']} · {b['judul'].removeprefix('Simulasi: ')}", "intensitas": 1})

        dampak = sorted(({"id": s["id"], "nama": s["nama"], "status": status[s["id"]][0],
                          "catatan": status[s["id"]][1]}
                         for s in SIMPUL if status[s["id"]][0] in ("kritis", "waspada", "isolasi")),
                        key=lambda d: -PERINGKAT[d["status"]])
        markas = max((d["status"] for d in dampak), key=PERINGKAT.get, default="normal")
        return {"markas": {**MARKAS, "status": markas, "gerbang": status["fw"][0]},
                "serangan": serangan, "dampak": dampak}

    def _baru_sejak(self, seq: int) -> list[dict]:
        return [e for e in self._peristiwa if e["seq"] > seq]

    def detak(self, layanan: dict, tampilan: Callable[[dict], dict], sejak: int) -> dict:
        self.maju(layanan)
        prediksi = self._prediksi(layanan)
        status, ancaman, _, _ = self._turunkan(layanan, prediksi)
        tampil = [tampilan(l) for l in layanan.values()]
        lalu_lintas = self._lalu_lintas()
        postur, kpi = self._postur(tampil, status, ancaman, lalu_lintas, prediksi)
        return {"versi": self.versi, "waktu": _iso(), "postur": postur, "kpi": kpi,
                "lalu_lintas": lalu_lintas, "cti": self._cti(prediksi, lengkap=False),
                "peristiwa": self._baru_sejak(sejak), "seq_terakhir": self._seq}

    def potret(self, layanan: dict, tampilan: Callable[[dict], dict]) -> dict:
        self.maju(layanan)
        prediksi = self._prediksi(layanan)
        status, ancaman, kerumunan, asal_kerumunan = self._turunkan(layanan, prediksi)
        tampil = [tampilan(l) for l in layanan.values()]
        lalu_lintas = self._lalu_lintas()
        postur, kpi = self._postur(tampil, status, ancaman, lalu_lintas, prediksi)
        prob = {k: v["persen"] for k, v in prediksi.items()}

        simpul = [{"id": s["id"], "nama": s["nama"], "ip": s["ip"], "port": s["port"], "zona": s["zona"],
                   "status": status[s["id"]][0], "catatan": status[s["id"]][1], "prob": prob.get(s["id"]),
                   "layanan": self._sebab.get(s["id"]) or PEMILIK_SIMPUL.get(s["id"])}
                  for s in SIMPUL]
        if ancaman:
            a = ancaman[0]
            simpul.insert(0, {"id": "ancaman", "nama": a["nama"], "ip": a["ip"], "port": a["port"],
                              "zona": "luar", "status": a["status"], "catatan": f"Cocok {a['ioc']}", "prob": None,
                              "layanan": a["layanan"]})
        st = {s["id"]: s["status"] for s in simpul}
        kabel = []
        for a, b, jenis in KABEL:
            if a not in st or b not in st:
                continue
            if "isolasi" in (st[a], st[b]):
                keadaan = "putus"
            elif jenis == "cadangan":
                keadaan = "diam"
            else:
                keadaan = max((st[a], st[b]), key=PERINGKAT.get)
            kabel.append({"dari": a, "ke": b, "jenis": jenis, "status": keadaan})

        # Fase 5 (audit #4): jarak dari pusat = ZONA jaringan; sudut = penanda tetap alamat IP (bukan geografi)
        titik = [{"ip": s["ip"], "port": s["port"], "nama": s["nama"], "r": s["r"], "sudut": sudut_dari(s["ip"]),
                  "zona": s["zona"], "status": status[s["id"]][0], "catatan": status[s["id"]][1],
                  "prob": prob.get(s["id"])}
                 for s in SIMPUL if "r" in s]
        titik += [{"ip": a["ip"], "port": a["port"], "nama": a["nama"], "r": .88, "sudut": sudut_dari(a["ip"]),
                   "zona": "luar", "status": a["status"], "catatan": f"Cocok {a['ioc']}", "prob": None} for a in ancaman]
        for i in range(kerumunan):
            ip = f"198.51.100.{120 + i * 7}"
            titik.append({"ip": ip, "port": 443, "nama": "Sumber trafik banjir", "r": round(.78 + (i % 5) * .04, 2),
                          "sudut": sudut_dari(ip), "zona": "luar", "status": "waspada", "catatan": "Bagian dari banjir permintaan",
                          "prob": None})

        return {
            "versi": self.versi, "waktu": _iso(), "postur": postur, "kpi": kpi,
            "topologi": {"simpul": simpul, "kabel": kabel},
            "radar": {"putaran_ms": PUTARAN_MS[postur["tingkat"]], "titik": titik},
            "lalu_lintas": lalu_lintas,
            "cti": self._cti(prediksi, lengkap=True), "soar": self._soar(layanan), "forensik": self._forensik(layanan),
            "kesiapan": self._kesiapan(layanan, prediksi),
            "deteksi": self._deteksi_tampil(prediksi),
            "peringatan": self._peringatan(layanan, prediksi),
            "linimasa": self._linimasa_tampil(),
            "peta": self._peta(status, ancaman, kerumunan, asal_kerumunan),
            "komando": self._komando(layanan), "manajemen": MANAJEMEN, "kebijakan": KEBIJAKAN,
            "ir": self._ir[::-1], "playbook_ringkas": PLAYBOOK_RINGKAS,
            "layanan": tampil, "batas_jam_backup": BATAS_JAM_BACKUP, "efek_langkah": self._efek,
            "peristiwa": list(self._peristiwa)[-30:], "seq_terakhir": self._seq,
        }


MENARA = Menara()
