# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
titik_periksa.py — Titik periksa bertanda tangan Ed25519 dengan kunci yang berevolusi.

Analogi: buku ekspedisi yang setiap beberapa halaman dibubuhi cap notaris. Cap hari ini sekaligus mengesahkan cap
yang akan dipakai besok, lalu cap hari ini dimusnahkan. Pencuri yang besok masuk kantor hanya menemukan cap besok,
jadi ia tidak bisa membuat ulang halaman-halaman yang sudah dicap kemarin.

Masalah yang ditutup (Dokumentasi Teknis §2.7 dan §2.9): HMAC memakai satu kunci untuk membuat sekaligus memeriksa.
Siapa pun yang memegang NS_AUDIT_KEY, termasuk penyerang yang membobol server, bisa menulis ulang riwayat dengan
sidik jari yang sah. Titik periksa menambah lapisan yang tidak bergantung pada kunci itu:

  1. Setiap titik periksa mencatat kepala kedua buku: jumlah entri dan SHA-256 kumulatif atas entri 1..n
     (h_k = SHA-256(h_{k-1} || JSON kanonik entri k), h_0 = 64 nol). Siapa pun bisa menghitungnya ulang.
  2. Titik periksa ke-i ditandatangani kunci Ed25519 periode i, dan memuat kunci publik periode i+1.
     Sesudah itu kunci privat periode i ditimpa di disk (berkas status hanya berisi kunci periode berjalan).
  3. Auditor cukup memegang sidik jari kunci AKAR (SHA-256 kunci publik periode 1; tercetak di LAPSIT dan tercatat
     di log audit sebagai KUNCI_TITIK_PERIKSA_DIBUAT). Ia menelusuri rantai kunci publik dari akar, memeriksa setiap
     tanda tangan, lalu mencocokkan kepala buku dengan berkas log: tools/verifikasi_titik_periksa.py.

Batas yang jujur:
  - Entri SESUDAH titik periksa terakhir belum dilindungi tanda tangan. Titik periksa dibuat setiap
    NS_TITIK_PERIKSA_SETIAP entri (bawaan 25) dan setiap kali LAPSIT diekspor.
  - Penghapusan kunci lama = berkas status ditimpa. Pada SSD atau sistem berkas berjurnal, sisa data lama bisa
    tertinggal di media; enkripsi disk penuh menutup celah itu.
  - Bila server sudah dibobol SEBELUM kunci akar dibuat, atau sidik jari akar tidak pernah dicatat di luar server
    (LAPSIT, berita acara), lapisan ini tidak menolong.
  - Hanya aktif bila log disimpan ke berkas (NS_AUDIT_KEY diatur). Mode demo tidak membuat titik periksa.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from .audit import HASH_AWAL, LogAudit

DOMAIN = b"nusantara-shield/titik-periksa/1\n"   # awalan tanda tangan: tidak bisa dipakai ulang untuk hal lain
VERSI_FORMAT = 1


def kanonik(entri: dict) -> bytes:
    return json.dumps(entri, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_kumulatif(daftar: list[dict], awal: str = HASH_AWAL) -> str:
    h = bytes.fromhex(awal)
    for e in daftar:
        h = hashlib.sha256(h + kanonik(e)).digest()
    return h.hex()


def kanonik_tanda_tangan(catatan: dict) -> bytes:
    """Bita yang ditandatangani: awalan domain + JSON kanonik catatan tanpa kolom tanda_tangan."""
    return DOMAIN + kanonik({k: v for k, v in catatan.items() if k != "tanda_tangan"})


def _publik(sk: Ed25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _mentah(sk: Ed25519PrivateKey) -> bytes:
    return sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


class TitikPeriksa:
    def __init__(self, buku: dict[str, LogAudit], setiap: int | None = None) -> None:
        self._buku = buku
        self._setiap = setiap or int(os.getenv("NS_TITIK_PERIKSA_SETIAP", "25"))
        self._berkas = Path(os.getenv("NS_TITIK_PERIKSA_FILE", "data/titik_periksa.jsonl"))
        self._berkas_kunci = Path(os.getenv("NS_TITIK_PERIKSA_KUNCI", "data/titik_periksa_kunci.json"))
        self._kunci = threading.Lock()
        self._sk: Ed25519PrivateKey | None = None
        self._terakhir: dict | None = None
        self._kepala: dict[str, tuple[int, str]] = {}      # nama buku → (jumlah, sha256 kumulatif) tersimpan cache
        self.aktif = False
        self.galat = ""
        self.sidik_jari_akar = ""
        self.demo = any(b.sementara for b in buku.values())
        if self.demo:
            self.galat = "Mode demo (NS_AUDIT_KEY belum diatur): log hanya di memori, titik periksa tidak dibuat."
            return
        try:
            self._siapkan()
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as e:
            self.galat = f"Titik periksa nonaktif: berkas status tidak terbaca ({e})."
        if not self.aktif:
            print(f"[PERINGATAN] {self.galat}")
            return
        for b in buku.values():
            b.saat_dicatat(self.mungkin_buat)

    # -- status kunci di disk ---------------------------------------------------
    def _simpan_kunci(self, sk: Ed25519PrivateKey, no_berikut: int) -> None:
        """Timpa berkas status secara atomik: hanya kunci periode berjalan yang tersisa (izin 600)."""
        self._berkas_kunci.parent.mkdir(parents=True, exist_ok=True)
        sementara = self._berkas_kunci.with_name(self._berkas_kunci.name + ".baru")
        fd = os.open(sementara, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"versi_format": VERSI_FORMAT, "no_berikut": no_berikut, "kunci_privat": _mentah(sk).hex()}, f)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(sementara, 0o600)
        os.replace(sementara, self._berkas_kunci)

    def _siapkan(self) -> None:
        catatan = []
        if self._berkas.exists():
            catatan = [json.loads(b) for b in self._berkas.read_text(encoding="utf-8").splitlines() if b.strip()]
        if not self._berkas_kunci.exists():
            if catatan:
                self.galat = ("Berkas kunci titik periksa hilang, padahal titik periksa sudah ada. Akar baru TIDAK dibuat "
                              "otomatis; periksa server lalu pulihkan berkas status.")
                return
            sk = Ed25519PrivateKey.generate()
            self._simpan_kunci(sk, 1)
            self._sk, self.aktif = sk, True
            self.sidik_jari_akar = hashlib.sha256(_publik(sk)).hexdigest()
            print(f"[TITIK PERIKSA] Kunci akar dibuat. Catat sidik jari akar di berita acara: {self.sidik_jari_akar}")
            pertama = next(iter(self._buku.values()))
            pertama.catat("sistem", "KUNCI_TITIK_PERIKSA_DIBUAT", {"sidik_jari_akar": self.sidik_jari_akar})
            return
        status = json.loads(self._berkas_kunci.read_text(encoding="utf-8"))
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(status["kunci_privat"]))
        pk = _publik(sk).hex()
        tertinggal = (status["no_berikut"] != len(catatan) + 1
                      or (catatan and catatan[-1].get("kunci_publik_berikut") != pk))
        if tertinggal:
            self.galat = ("Status kunci tidak sesuai dengan berkas titik periksa (titik periksa hilang, disunting, atau "
                          "server berhenti di tengah rotasi). Akar baru TIDAK dibuat otomatis; periksa dengan "
                          "tools/verifikasi_titik_periksa.py.")
            return
        self._sk, self.aktif = sk, True
        self._terakhir = catatan[-1] if catatan else None
        akar_pk = bytes.fromhex(catatan[0]["kunci_publik"]) if catatan else _publik(sk)
        self.sidik_jari_akar = hashlib.sha256(akar_pk).hexdigest()

    # -- pembuatan titik periksa -----------------------------------------------------
    def _kepala_buku(self, nama: str, buku: LogAudit) -> dict:
        entri = buku.salinan_entri()
        n_lama, h_lama = self._kepala.get(nama, (0, HASH_AWAL))
        if n_lama > len(entri):
            n_lama, h_lama = 0, HASH_AWAL
        h = sha256_kumulatif(entri[n_lama:], h_lama)
        self._kepala[nama] = (len(entri), h)
        return {"jumlah": len(entri), "sha256_kumulatif": h}

    def _baru_sejak_terakhir(self) -> int:
        lama = self._terakhir["log"] if self._terakhir else {}
        return sum(b.jumlah - lama.get(n, {}).get("jumlah", 0) for n, b in self._buku.items())

    def mungkin_buat(self) -> None:
        if self.aktif and self._baru_sejak_terakhir() >= self._setiap:
            self.buat("BERKALA")

    def buat(self, alasan: str) -> dict | None:
        """Tandatangani kepala semua buku dengan kunci periode berjalan, sahkan kunci berikutnya, hapus kunci lama."""
        if not self.aktif:
            return None
        with self._kunci:
            if alasan == "BERKALA" and self._baru_sejak_terakhir() < self._setiap:
                return None                                    # sudah dibuat oleh pemanggil lain
            sk_berikut = Ed25519PrivateKey.generate()
            no = (self._terakhir["no"] + 1) if self._terakhir else 1
            catatan = {
                "versi_format": VERSI_FORMAT,
                "no": no,
                "waktu": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "alasan": alasan,
                "log": {n: self._kepala_buku(n, b) for n, b in self._buku.items()},
                "kunci_publik": _publik(self._sk).hex(),
                "kunci_publik_berikut": _publik(sk_berikut).hex(),
            }
            catatan["tanda_tangan"] = self._sk.sign(kanonik_tanda_tangan(catatan)).hex()
            self._berkas.parent.mkdir(parents=True, exist_ok=True)
            with self._berkas.open("a", encoding="utf-8") as f:   # 1) catatan bertanda tangan tersimpan dulu
                f.write(json.dumps(catatan, ensure_ascii=False) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._simpan_kunci(sk_berikut, no + 1)              # 2) baru kunci lama ditimpa kunci berikutnya
            self._sk, self._terakhir = sk_berikut, catatan
            return catatan

    def ringkasan(self, catatan: dict | None = None) -> dict:
        """Untuk LAPSIT dan API: cukup untuk auditor menjalankan tools/verifikasi_titik_periksa.py."""
        c = catatan or self._terakhir
        return {"aktif": self.aktif, "demo": self.demo, "galat": self.galat, "sidik_jari_akar": self.sidik_jari_akar,
                "no": c["no"] if c else None, "waktu": c["waktu"] if c else None,
                "log": {n: v["jumlah"] for n, v in c["log"].items()} if c else {}}
