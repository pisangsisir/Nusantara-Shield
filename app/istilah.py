# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
istilah.py — SATU-SATUNYA tempat label manusiawi di aplikasi ini (temuan audit F-01, F-10, F-12).

Analogi: papan nama ruangan di sebuah gedung. Kalau nama ruangan berganti, petugas cukup
mengganti papan namanya, bukan membongkar dinding. Semua kode (backend, frontend, tes)
membaca label dari kamus ini, jadi mengganti istilah TIDAK PERNAH memecahkan pytest.

Cara mengganti terminologi (misalnya dari istilah korporat ke istilah Pussiber AD):
  - ubah NILAI di sebelah kanan tanda titik dua, JANGAN ubah KUNCI di sebelah kiri;
  - simpan berkas, nyalakan ulang server, jalankan `pytest -q`.

Kunci dibaca oleh Python (lewat ISTILAH["..."]) dan oleh browser (lewat GET /api/istilah).
Semua nama orang FIKTIF.
"""

from __future__ import annotations

from .versi import VERSI

ISTILAH: dict = {
    # --- identitas aplikasi -------------------------------------------------------------
    "produk": "Dasbor Pertahanan Siber Satuan",
    "nama_versi": f"Nusantara Shield v{VERSI}",   # nomor dari app/versi.py; jangan ditulis langsung

    # --- nama peran akun (nilai teknis "operator"/"pengamat" tetap huruf kecil di API) -----
    "peran_operator": "Operator",
    "peran_pengamat": "Pengamat",
    "tim_insiden": "TTIS Satuan",              # Tim Tanggap Insiden Siber (Perpres 82/2022)

    # --- laporan otomatis ke manajemen (Automated IR Blast) ------------------------------
    "laporan": "Laporan Situasi (LAPSIT)",  # nama lengkap laporan
    "laporan_singkat": "IR",               # dipakai di chip log dan prefiks nomor (IR-2026-001)

    # --- penerima laporan: diberi tahu, TIDAK dimintai izin ----------------------------
    "manajemen": [
        {"id": "ciso", "jabatan": "Dansat", "kepanjangan": "Komandan Satuan",
         "nama": "Kolonel Ratna Kusumawati (fiktif)"},
        {"id": "vp_eng", "jabatan": "Kasi Siber", "kepanjangan": "Kepala Seksi Siber Satuan",
         "nama": "Mayor Hendra Wijaya (fiktif)"},
    ],

    # --- jabatan PIC teknis cabang (Quick Call) -----------------------------------------
    "pic_cabang_utama": "Perwira Siber Markas",
    "pic_cabang": "Perwira Siber Satuan",
    "pic_basis_data": "Operator Basis Data",

    # --- label tombol & status di Action Center ----------------------------------------
    "tombol_isolasi": "⚡ EKSEKUSI ISOLASI",
    "tombol_isolasi_tahan": "tahan 0,6 detik untuk mengeksekusi",
    "tombol_pulihkan": "♻ PULIHKAN",
    "tombol_tutup": "Tutup insiden",
    "tombol_hubungi": "📞 HUBUNGI PERWIRA SATUAN",
    "status_terisolasi": "✓ TERISOLASI",
    "quick_call": "Quick Call",

    # --- Fase 4: rantai bukti forensik & isolasi darurat ---------------------------------
    "langkah_bukti": "Amankan bukti",
    "buku_bukti": "Buku Rantai Bukti",
    "status_bukti_aman": "BUKTI DIAMANKAN",
    "tombol_amankan_bukti": "🔒 AMANKAN BUKTI SEKARANG",
    "tombol_darurat": "⚠ ISOLASI DARURAT",
    "tombol_darurat_tahan": "tahan 1,5 detik · tanpa bukti · alasan dicatat permanen",
    "pesan_jangan_restart": "sistem sedang diisolasi {tim}, jangan di-restart",

    # --- triase peringatan: penutupan oleh Operator (tercatat di Buku Rantai Bukti) ----------
    # Penyebutan pertama di dokumen: "Positif Palsu (False Positive)"; label UI dan log: istilah asingnya saja.
    "tutup_selesai": "Selesai ditangani",
    "tutup_fp": "False Positive",
    "tombol_tutup_peringatan": "Tutup peringatan",
    "kesiapan": "Kesiapan Siber",
    # cyber drill untuk Operator (app/drill.py); dasar: Perpres 82/2022 Pasal 15 (simulasi tanggap insiden)
    "drill": "Drill Kesiapan",

    # --- nama resmi komponen (penyebutan pertama di dokumen disertai istilah aslinya dalam kurung) ---
    "mesin_aturan": "Mesin Deteksi Aturan",     # rule-based detection engine (app/deteksi.py)
    "mesin_anomali": "Mesin Deteksi Anomali",   # anomaly detection engine, AI lokal (app/ai_anomali.py)
    "kepatuhan_pencadangan": "Kepatuhan Pencadangan",   # backup compliance (pelajaran PDNS 2024)

    # --- LAPSIT: blok pengesahan dua tanda tangan (dua kunci juga di atas kertas) ---------------
    "ttd_judul": "Pengesahan",
    "ttd_pembuat": "Operator jaga (pembuat laporan)",
    "ttd_mengetahui": "Mengetahui",
}


def nama_manajemen() -> list[str]:
    """Daftar jabatan penerima laporan, sesuai urutan di kamus."""
    return [m["jabatan"] for m in ISTILAH["manajemen"]]


def kepada_manajemen() -> str:
    """'Dansat & Kasi Siber' — dipakai di teks playbook dan log."""
    return " & ".join(nama_manajemen())


def pesan_jangan_restart() -> str:
    return ISTILAH["pesan_jangan_restart"].format(tim=ISTILAH["tim_insiden"])
