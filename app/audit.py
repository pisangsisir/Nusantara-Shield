# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
audit.py — Buku catatan kejadian yang "ketahuan bila dicoret".

Analogi: buku ekspedisi bernomor halaman, di mana setiap halaman memuat
"sidik jari" halaman sebelumnya. Bila satu halaman di tengah diubah atau
disobek, sidik jari di halaman sesudahnya tidak lagi cocok, sehingga
manipulasi langsung ketahuan.

Sidik jari dibuat dengan HMAC (hash + kunci rahasia). Tanpa kunci, penyerang
yang bisa membuka berkas log pun tidak dapat menghitung ulang seluruh rantai.

Minimisasi data: yang dicatat hanya SIAPA (nama akun), APA (jenis aksi), dan
detail teknis seperlunya. Alamat IP pengunjung dan nilai mentah pencarian
tidak disimpan.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path

HASH_AWAL = "0" * 64  # "halaman nol" sebelum catatan pertama


class LogAudit:
    """Fase 4: kelas yang sama dipakai DUA buku — log audit (siapa melakukan apa) dan buku rantai
    bukti (barang bukti apa yang diamankan). Keduanya berantai HMAC dengan kunci NS_AUDIT_KEY."""

    def __init__(self, env_berkas: str = "NS_AUDIT_FILE", berkas_bawaan: str = "data/audit_log.jsonl",
                 nama: str = "log audit") -> None:
        kunci_env = os.getenv("NS_AUDIT_KEY")
        self._kunci_sementara = not kunci_env
        # Tanpa kunci tetap: log hanya di memori (hilang saat aplikasi dimatikan).
        self._kunci = (kunci_env or secrets.token_hex(32)).encode()
        berkas = os.getenv(env_berkas, berkas_bawaan)
        self._berkas = None if self._kunci_sementara else Path(berkas)
        self._entri: list[dict] = []
        self._kunci_tulis = threading.Lock()
        self._pengamat: list = []            # dipanggil sesudah entri tersimpan (titik periksa Ed25519)
        if self._kunci_sementara:
            print(f"[DEMO] NS_AUDIT_KEY belum diatur: {nama} hanya disimpan di memori.")
        elif self._berkas and self._berkas.exists():
            self._muat_dari_berkas()

    # -- perhitungan sidik jari ------------------------------------------------
    def _sidik_jari(self, entri: dict) -> str:
        isi = {k: v for k, v in entri.items() if k != "hash"}
        kanonik = json.dumps(isi, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hmac.new(self._kunci, kanonik.encode(), hashlib.sha256).hexdigest()

    def _muat_dari_berkas(self) -> None:
        with self._berkas.open(encoding="utf-8") as f:
            self._entri = [json.loads(baris) for baris in f if baris.strip()]
        hasil = self.verifikasi()
        if not hasil["utuh"]:
            # Jangan diam-diam melanjutkan di atas log yang rusak.
            raise RuntimeError(f"Log audit rusak saat dimuat: {hasil['pesan']}")

    # -- operasi utama --------------------------------------------------------
    def catat(self, aktor: str, aksi: str, detail: dict | None = None) -> dict:
        with self._kunci_tulis:
            sebelumnya = self._entri[-1]["hash"] if self._entri else HASH_AWAL
            entri = {
                "urutan": len(self._entri) + 1,
                "waktu": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "aktor": aktor,
                "aksi": aksi,
                "detail": detail or {},
                "hash_sebelumnya": sebelumnya,
            }
            entri["hash"] = self._sidik_jari(entri)
            self._entri.append(entri)
            if self._berkas:
                self._berkas.parent.mkdir(parents=True, exist_ok=True)
                with self._berkas.open("a", encoding="utf-8") as f:  # hanya menambah, tidak menimpa
                    f.write(json.dumps(entri, ensure_ascii=False) + "\n")
                    f.flush()
                    os.fsync(f.fileno())    # v5.4.1: entri sudah di disk sebelum titik periksa mana pun merujuknya
        for fungsi in list(self._pengamat):         # di luar kunci tulis: pengamat boleh membaca buku ini
            fungsi()
        return entri

    def saat_dicatat(self, fungsi) -> None:
        """Daftarkan fungsi tanpa argumen yang dipanggil setiap kali entri baru tersimpan."""
        self._pengamat.append(fungsi)

    @property
    def berkas(self):
        return self._berkas

    def salinan_entri(self) -> list[dict]:
        with self._kunci_tulis:
            return [dict(e) for e in self._entri]

    def daftar(self, batas: int = 50) -> list[dict]:
        return list(reversed(self._entri[-batas:]))  # terbaru di atas

    def verifikasi(self) -> dict:
        sebelumnya = HASH_AWAL
        for i, e in enumerate(self._entri, start=1):
            if e.get("urutan") != i:
                return {"utuh": False, "jumlah": len(self._entri),
                        "pesan": f"Nomor urut loncat di entri ke-{i}"}
            if e.get("hash_sebelumnya") != sebelumnya:
                return {"utuh": False, "jumlah": len(self._entri),
                        "pesan": f"Rantai putus di entri #{i}"}
            if not hmac.compare_digest(self._sidik_jari(e), e.get("hash", "")):
                return {"utuh": False, "jumlah": len(self._entri),
                        "pesan": f"Isi entri #{i} telah diubah"}
            sebelumnya = e["hash"]
        return {"utuh": True, "jumlah": len(self._entri),
                "hash_terakhir": sebelumnya,
                "pesan": "Rantai audit utuh, tidak ada manipulasi terdeteksi"}

    @property
    def sementara(self) -> bool:
        return self._kunci_sementara

    def entri_utuh(self, entri: dict) -> bool:
        """Sidik jari SATU entri masih cocok dengan isinya (pemeriksaan cepat, tanpa menelusuri rantai)."""
        return hmac.compare_digest(self._sidik_jari(entri), entri.get("hash", ""))

    def cari(self, aksi: str, **syarat) -> list[dict]:
        """Entri dengan aksi tertentu yang detail-nya cocok dengan semua syarat (tertua lebih dulu)."""
        return [e for e in self._entri if e["aksi"] == aksi
                and all(e["detail"].get(k) == v for k, v in syarat.items())]

    @property
    def jumlah(self) -> int:
        return len(self._entri)

    def _uji_rusak(self, indeks: int, kolom: str, nilai) -> None:
        """Hanya untuk pengujian otomatis: sengaja merusak satu entri."""
        self._entri[indeks][kolom] = nilai


LOG = LogAudit()
