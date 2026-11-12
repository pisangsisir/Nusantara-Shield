# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
mitre.py — Label teknik MITRE ATT&CK® untuk setiap aturan deteksi dan skenario latihan.

Analogi: kode pasal di berita acara. Penyidik di mana pun langsung paham "T1110" tanpa membaca
kronologi lengkap, sama seperti analis SOC di satuan lain membaca peringatan kita.

Prinsip:
- Tabel statis di server: luring, tanpa unduhan dan tanpa tautan keluar.
- Pemetaan dilakukan tim sendiri sebagai rujukan, bukan sertifikasi oleh MITRE.
- AI lokal sengaja TIDAK diberi label: ia menilai pola lalu lintas, bukan mengenali teknik tertentu.
- MITRE ATT&CK® adalah merek dagang terdaftar The MITRE Corporation.
"""

from __future__ import annotations

ENTERPRISE, ICS = "Enterprise", "ICS"

TEKNIK: dict[str, tuple[str, str]] = {
    "T1046": ("Network Service Discovery", ENTERPRISE),
    "T1078": ("Valid Accounts", ENTERPRISE),
    "T1110": ("Brute Force", ENTERPRISE),
    "T1486": ("Data Encrypted for Impact", ENTERPRISE),
    "T1490": ("Inhibit System Recovery", ENTERPRISE),
    "T1498": ("Network Denial of Service", ENTERPRISE),
    "T0855": ("Unauthorized Command Message", ICS),
    "T0886": ("Remote Services", ICS),
}

# kunci = id aturan mesin deteksi aturan (app/deteksi.py) atau id skenario latihan (app/data_contoh.py)
PEMETAAN: dict[str, tuple[str, ...]] = {
    # aturan deteksi
    "login_gagal": ("T1110",),
    "login_tembus": ("T1078", "T1110"),
    "pindai_port": ("T1046",),
    "ot_tanpa_izin": ("T0886",),
    "tulis_ot_luar_jadwal": ("T0855",),
    "rantai_it_ot": ("T0886", "T0855"),
    # skenario latihan insiden
    "ransomware": ("T1486",),
    "backup_dimatikan": ("T1490",),
    "ddos": ("T1498",),
    "sabotase_ot": ("T0886", "T0855"),
    # v5.4.2: insiden dari temuan log asli memakai label ATURAN temuannya; ini hanya cadangan bila tidak ada
    "intrusi_log": ("T1078",),
}


def teknik(kunci: str | None) -> list[dict]:
    """[{"id", "nama", "matriks"}] untuk satu aturan/skenario; kosong bila tidak dipetakan."""
    return [{"id": t, "nama": TEKNIK[t][0], "matriks": TEKNIK[t][1]} for t in PEMETAAN.get(kunci or "", ())]


def ringkas(kunci: str | None) -> str:
    """'T0886 Remote Services (ICS); T0855 …' untuk log dan LAPSIT; '' bila tidak dipetakan."""
    return "; ".join(f"{t['id']} {t['nama']}" + (" (ICS)" if t["matriks"] == ICS else "") for t in teknik(kunci))
