# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
ai_anomali.py — mesin deteksi anomali lokal (AI) untuk Nusantara Shield.

Analogi: satpam lama yang hafal "suasana normal" gedung. Ia tidak perlu daftar buronan
(signature) untuk curiga; cukup melihat ada yang tidak biasa: pintu gudang dibuka 60 kali
semenit, atau truk keluar membawa barang jauh lebih banyak dari biasanya.

Cara kerja:
1. SAAT SERVER MENYALA, model Isolation Forest (scikit-learn) dilatih dari PROFIL NORMAL
   SINTETIS lalu lintas aset (enam ciri, lihat FITUR). Tidak ada berkas model dari luar,
   tidak ada unduhan, tidak ada pemanggilan API: semuanya terjadi di memori server ini.
2. SETIAP KALI KEADAAN BERUBAH, ciri lalu lintas tiap aset dinilai. Skor anomali 0..1
   (≈0,4 normal, ≥0,58 tidak wajar). Penilaian 9 aset sekaligus memakan beberapa milidetik
   dan hasilnya disimpan (cache), jadi tidak dihitung ulang tiap detik bila tidak ada perubahan.
3. Skor di atas ambang diubah menjadi PELUANG SERANGAN (≥ 50%) yang digabung dengan peluang
   dari kabar CTI di app/telemetri.py: 1 − (1 − p_CTI)(1 − p_AI).
4. Setiap deteksi disertai ALASAN (explainability): ciri mana yang paling menyimpang dari
   kebiasaan, misalnya "perintah tulis Modbus 10× normal".

Batas yang jujur: di purwarupa, ciri lalu lintas adalah DATA SINTETIS (profil normal dan
pola latihan). Penerapan nyata mengambil ciri dari sensor satuan (mis. Wazuh, Suricata, Zeek).
Keputusan memutus jaringan TETAP di tangan operator (human-in-the-loop).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from functools import lru_cache

import numpy as np
from sklearn.ensemble import IsolationForest

# --- ciri lalu lintas per aset (urutan = kolom matriks) ---------------------------------
# (kunci, label umum, label khusus aset OT/Modbus)
FITUR: list[tuple[str, str, str]] = [
    ("koneksi", "jumlah koneksi", "jumlah koneksi"),
    ("volume", "volume data", "volume data"),
    ("port_unik", "ragam port tujuan", "ragam port tujuan"),
    ("gagal_login", "login gagal", "login gagal"),
    ("perintah_tulis", "operasi tulis berkas", "perintah tulis Modbus"),
    ("tujuan_luar", "porsi koneksi ke luar jaringan", "porsi koneksi ke luar jaringan"),
]
#  Nilai rata-rata profil normal (koneksi & volume dinyatakan sebagai rasio terhadap kebiasaan aset).
RATA_NORMAL = np.array([1.0, 1.0, 4.0, 0.6, 6.0, 0.05])

# --- pola latihan & pola insiden (nilai mutlak keenam ciri) ------------------------------
POLA: dict[str, dict] = {
    "modbus_tulis_asing": {"nama": "perintah Modbus tak wajar", "nilai": [2.5, 1.3, 4.0, 0.6, 60.0, 0.40]},
    "eksfiltrasi":        {"nama": "pengiriman data besar ke luar", "nilai": [2.0, 9.0, 5.0, 0.6, 6.0, 0.75]},
    "enkripsi_massal":    {"nama": "penulisan berkas massal", "nilai": [1.5, 4.0, 9.0, 0.6, 80.0, 0.10]},
    "banjir":             {"nama": "banjir koneksi", "nilai": [25.0, 6.0, 4.0, 0.6, 6.0, 0.30]},
    "akses_admin_aneh":   {"nama": "akses admin tak wajar", "nilai": [1.4, 1.2, 6.0, 15.0, 20.0, 0.10]},
    "akses_jarak_jauh":   {"nama": "akses jarak jauh tak wajar", "nilai": [3.0, 1.5, 5.0, 10.0, 6.0, 0.25]},
}
#  Skenario latihan insiden → pola lalu lintas aset yang terdampak
POLA_SKENARIO: dict[str, str] = {
    "ransomware": "enkripsi_massal",
    "ddos": "banjir",
    "backup_dimatikan": "akses_admin_aneh",
    "sabotase_ot": "modbus_tulis_asing",
}

AMBANG_AI = 0.58          # skor ≥ ambang = lalu lintas tidak wajar
KEMIRINGAN = 4.0          # skor 0,58 → peluang 50%; skor 0,67 → ≈86%
PELUANG_MAKS = 0.95
BENIH = 2026              # benih acak tetap: model selalu sama setiap server menyala (dapat diaudit)
JUMLAH_SAMPEL = 1500
JUMLAH_POHON = 100


def profil_normal(benih: int = BENIH, n: int = JUMLAH_SAMPEL) -> np.ndarray:
    """Data latih sintetis: ribuan menit lalu lintas aset yang wajar."""
    g = np.random.default_rng(benih)
    return np.column_stack([
        g.normal(1.0, 0.15, n).clip(0.3),     # koneksi (rasio)
        g.normal(1.0, 0.20, n).clip(0.2),     # volume (rasio)
        g.normal(4.0, 1.2, n).clip(1.0),      # ragam port tujuan
        g.poisson(0.6, n),                    # login gagal per menit
        g.normal(6.0, 2.0, n).clip(0.0),      # operasi/perintah tulis per menit
        g.normal(0.05, 0.03, n).clip(0, 1),   # porsi koneksi ke luar
    ])


@lru_cache(maxsize=64)
def ciri_normal(aset_id: str) -> tuple[float, ...]:
    """Ciri lalu lintas WAJAR satu aset: dekat rata-rata, dengan sidik kecil yang tetap per aset."""
    k = sum(ord(c) for c in aset_id) % 7
    geser = np.array([0.02, -0.01, 0.1, 0.0, 0.2, 0.002]) * k
    return tuple(float(round(v, 3)) for v in RATA_NORMAL + geser)


@lru_cache(maxsize=64)
def ciri_pola(pola: str) -> tuple[float, ...]:
    return tuple(float(v) for v in POLA[pola]["nilai"])


@dataclass
class HasilAI:
    skor: float
    peluang: float
    anomali: bool
    alasan: str


class DetektorAnomali:
    """Isolation Forest yang dilatih lokal saat server menyala."""

    def __init__(self, benih: int = BENIH):
        mulai = time.perf_counter()
        data = profil_normal(benih)
        self.model = IsolationForest(n_estimators=JUMLAH_POHON, max_samples=256, random_state=benih)
        self.model.fit(data)
        self.rata = data.mean(axis=0)
        self.latih_ms = round((time.perf_counter() - mulai) * 1000, 1)
        self.skor_ms = 0.0
        self._cache: dict[tuple, dict[str, HasilAI]] = {}

    # -- penilaian ---------------------------------------------------------------------
    def _alasan(self, ciri: np.ndarray, modbus: bool) -> str:
        """Dua ciri yang paling menyimpang dari kebiasaan, dalam bahasa manusia."""
        kali = ciri / np.maximum(self.rata, 0.05)
        urut = np.argsort(-kali)[:2]
        bagian = []
        for i in urut:
            if kali[i] < 1.5:
                continue
            label = FITUR[i][2] if modbus else FITUR[i][1]
            bagian.append(f"{label} {kali[i]:.0f}× normal")
        return ", ".join(bagian) or "kombinasi ciri tidak lazim"

    def nilai(self, ciri_aset: dict[str, tuple[float, ...]], modbus: set[str] | None = None) -> dict[str, HasilAI]:
        """Skor anomali semua aset sekaligus. Hasil disimpan per keadaan (cache)."""
        kunci = tuple(sorted(ciri_aset.items()))
        if kunci in self._cache:
            return self._cache[kunci]
        modbus = modbus or set()
        ids = list(ciri_aset)
        X = np.array([ciri_aset[i] for i in ids], dtype=float)
        mulai = time.perf_counter()
        skor = -self.model.score_samples(X)          # 0..1; ≈0,4 wajar, mendekati 1 sangat tidak wajar
        self.skor_ms = round((time.perf_counter() - mulai) * 1000, 2)
        hasil = {}
        for aid, s, ciri in zip(ids, skor, X):
            s = float(s)
            anomali = s >= AMBANG_AI
            p = min(PELUANG_MAKS, 0.5 + (s - AMBANG_AI) * KEMIRINGAN) if anomali else 0.0
            hasil[aid] = HasilAI(skor=round(s, 3), peluang=round(p, 3), anomali=anomali,
                                 alasan=self._alasan(ciri, aid in modbus) if anomali else "")
        if len(self._cache) > 256:
            self._cache.clear()
        self._cache[kunci] = hasil
        return hasil

    def ringkasan(self) -> dict:
        return {"model": "Isolation Forest (scikit-learn)", "pohon": JUMLAH_POHON, "fitur": len(FITUR),
                "sampel_latih": JUMLAH_SAMPEL, "ambang": AMBANG_AI, "latih_ms": self.latih_ms,
                "skor_ms": self.skor_ms, "luring": True}


DETEKTOR = DetektorAnomali()
