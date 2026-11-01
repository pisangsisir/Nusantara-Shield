#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
Verifikasi titik periksa Ed25519 log audit dan Buku Rantai Bukti TANPA kunci rahasia apa pun.

Untuk auditor: yang dibutuhkan hanya SIDIK JARI KUNCI AKAR (64 karakter heksadesimal) dari LAPSIT atau berita
acara, berkas data/titik_periksa.jsonl, dan berkas log. NS_AUDIT_KEY tidak diperlukan. Alat ini hanya memakai
pustaka bawaan Python (Ed25519 diperiksa dengan implementasi rujukan RFC 8032 §6), tidak mengimpor kode aplikasi,
dan tidak membuka jaringan.

Yang diperiksa:
  1. kunci publik titik periksa #1 cocok dengan sidik jari akar;
  2. kunci publik titik periksa #i+1 sama dengan "kunci_publik_berikut" yang disahkan titik periksa #i;
  3. tanda tangan setiap titik periksa sah;
  4. untuk setiap buku: jumlah entri tidak pernah mundur, dan SHA-256 kumulatif entri 1..n di berkas log sama
     dengan yang ditandatangani.

Pemakaian (dari akar repo):
    python3 tools/verifikasi_titik_periksa.py --akar <sidik jari akar>
    python3 tools/verifikasi_titik_periksa.py --akar <...> --titik data/titik_periksa.jsonl \\
        --log audit_log=data/audit_log.jsonl --log rantai_bukti=data/rantai_bukti.jsonl

Kode keluar: 0 = semua titik periksa sah dan log cocok, 1 = ada yang rusak atau tidak cocok, 2 = tidak bisa
memeriksa (berkas tidak ada, argumen salah).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

DOMAIN = b"nusantara-shield/titik-periksa/1\n"
HASH_AWAL = "0" * 64
LOG_BAWAAN = {"audit_log": "data/audit_log.jsonl", "rantai_bukti": "data/rantai_bukti.jsonl"}

# ---------------------------------------------------------------- Ed25519 (RFC 8032 §6, hanya verifikasi)
_P = 2 ** 255 - 19
_Q = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_AKAR_M1 = pow(2, (_P - 1) // 4, _P)


def _tambah(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % _P
    B = (a[1] + a[0]) * (b[1] + b[0]) % _P
    C = 2 * a[3] * b[3] * _D % _P
    D = 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _kali(s, a):
    hasil = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            hasil = _tambah(hasil, a)
        a = _tambah(a, a)
        s >>= 1
    return hasil


def _sama(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _pulihkan_x(y, tanda):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    if x2 == 0:
        return None if tanda else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _AKAR_M1 % _P
    if (x * x - x2) % _P:
        return None
    if (x & 1) != tanda:
        x = _P - x
    return x


def _buka(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    tanda, y = y >> 255, y & ((1 << 255) - 1)
    x = _pulihkan_x(y, tanda)
    return None if x is None else (x, y, 1, x * y % _P)


_GY = 4 * pow(5, _P - 2, _P) % _P
_G = (_pulihkan_x(_GY, 0), _GY, 1, _pulihkan_x(_GY, 0) * _GY % _P)


def ed25519_sah(publik: bytes, pesan: bytes, ttd: bytes) -> bool:
    if len(publik) != 32 or len(ttd) != 64:
        return False
    A, R = _buka(publik), _buka(ttd[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(ttd[32:], "little")
    if s >= _Q:
        return False
    h = int.from_bytes(hashlib.sha512(ttd[:32] + publik + pesan).digest(), "little") % _Q
    return _sama(_kali(s, _G), _tambah(R, _kali(h, A)))


# ---------------------------------------------------------------- titik periksa
def kanonik(o: dict) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def baca_jsonl(berkas: Path) -> list[dict]:
    hasil = []
    for nomor, baris in enumerate(berkas.read_text(encoding="utf-8").splitlines(), start=1):
        if baris.strip():
            try:
                hasil.append(json.loads(baris))
            except json.JSONDecodeError:
                raise ValueError(f"{berkas} baris {nomor} bukan JSON yang sah")
    return hasil


def kepala(entri: list[dict], n: int) -> str:
    h = bytes.fromhex(HASH_AWAL)
    for e in entri[:n]:
        h = hashlib.sha256(h + kanonik(e)).digest()
    return h.hex()


def periksa(titik: list[dict], akar: str, log: dict[str, list[dict]]) -> tuple[bool, list[str]]:
    pesan: list[str] = []
    if not titik:
        return False, ["[RUSAK] Berkas titik periksa kosong: tidak ada yang bisa dicocokkan dengan akar."]
    if hashlib.sha256(bytes.fromhex(titik[0].get("kunci_publik", ""))).hexdigest() != akar:
        return False, ["[RUSAK] Kunci publik titik periksa #1 tidak cocok dengan sidik jari akar dari berita acara: "
                       "rantai titik periksa diganti atau berasal dari sistem lain."]
    jumlah_lama: dict[str, int] = {}
    for i, c in enumerate(titik, start=1):
        if c.get("no") != i:
            return False, pesan + [f"[RUSAK] Nomor titik periksa loncat: tertulis #{c.get('no')}, seharusnya #{i}."]
        if i > 1 and c.get("kunci_publik") != titik[i - 2].get("kunci_publik_berikut"):
            return False, pesan + [f"[RUSAK] Kunci titik periksa #{i} bukan kunci yang disahkan titik periksa #{i - 1}."]
        try:
            sah = ed25519_sah(bytes.fromhex(c["kunci_publik"]), DOMAIN + kanonik(
                {k: v for k, v in c.items() if k != "tanda_tangan"}), bytes.fromhex(c.get("tanda_tangan", "")))
        except (KeyError, ValueError):
            sah = False
        if not sah:
            return False, pesan + [f"[RUSAK] Tanda tangan titik periksa #{i} tidak sah: isinya diubah sesudah "
                                   "ditandatangani, atau ditandatangani kunci lain."]
        for nama, kp in c.get("log", {}).items():
            n = kp["jumlah"]
            if log.get(nama) is None:
                if n:                                  # buku berisi, tetapi berkasnya tidak ada atau tidak diberikan
                    return False, pesan + [f"[RUSAK] Berkas buku '{nama}' tidak diberikan atau tidak ditemukan, padahal "
                                           f"titik periksa #{i} mencatat {n} entri (pakai --log {nama}=BERKAS)."]
            entri_buku = log.get(nama) or []           # None + 0 entri: buku belum pernah berisi, berkas belum dibuat
            if n < jumlah_lama.get(nama, 0):
                return False, pesan + [f"[RUSAK] Titik periksa #{i}: jumlah entri {nama} mundur."]
            if len(entri_buku) < n:
                return False, pesan + [f"[RUSAK] {nama} dipotong: titik periksa #{i} mencatat {n} entri, berkas hanya "
                                       f"berisi {len(entri_buku)}."]
            if kepala(entri_buku, n) != kp["sha256_kumulatif"]:
                return False, pesan + [f"[RUSAK] {nama}: entri 1–{n} tidak sama dengan yang ditandatangani di titik "
                                       f"periksa #{i}. Ada entri yang diubah, dihapus, atau disisipkan."]
            jumlah_lama[nama] = n
        pesan.append(f"[SAH]   Titik periksa #{i} · {c.get('waktu')} · {c.get('alasan')} · "
                     + ", ".join(f"{n} {v['jumlah']} entri" for n, v in c.get("log", {}).items()))
    for nama in dict.fromkeys([*log, *jumlah_lama]):
        entri = log.get(nama)
        if entri is None:
            if nama in jumlah_lama:
                pesan.append(f"[UTUH]  {nama}: 0 entri (buku belum pernah berisi; berkasnya belum dibuat).")
            continue
        n = jumlah_lama.get(nama, 0)
        pesan.append(f"[UTUH]  {nama}: {n} entri dilindungi tanda tangan"
                     + (f"; {len(entri) - n} entri sesudah titik periksa terakhir belum dilindungi." if len(entri) > n
                        else "."))
    return True, pesan


def main(argv: list[str] | None = None, keluar=sys.stdout) -> int:
    p = argparse.ArgumentParser(prog="verifikasi_titik_periksa.py",
                                description="Verifikasi titik periksa Ed25519 tanpa kunci rahasia.")
    p.add_argument("--akar", required=True, help="sidik jari kunci akar (64 heksadesimal) dari LAPSIT/berita acara")
    p.add_argument("--titik", default="data/titik_periksa.jsonl", help="berkas titik periksa")
    p.add_argument("--log", action="append", default=[], metavar="NAMA=BERKAS",
                   help="berkas buku; bawaan: audit_log=data/audit_log.jsonl, rantai_bukti=data/rantai_bukti.jsonl")
    a = p.parse_args(argv)
    tulis = lambda teks="": print(teks, file=keluar)
    akar = a.akar.strip().lower()
    if len(akar) != 64 or any(ch not in "0123456789abcdef" for ch in akar):
        tulis("GAGAL: --akar harus 64 karakter heksadesimal.")
        return 2
    peta = dict(x.split("=", 1) for x in a.log if "=" in x) or LOG_BAWAAN
    try:
        titik = baca_jsonl(Path(a.titik))
        # Berkas buku yang tidak ada = None: diterima hanya bila titik periksa mencatat buku itu 0 entri.
        log = {n: (baca_jsonl(Path(b)) if Path(b).exists() else None) for n, b in peta.items()}
    except FileNotFoundError as e:
        tulis(f"GAGAL: berkas tidak ditemukan: {e.filename}")
        return 2
    except ValueError as e:
        tulis(f"[RUSAK] {e}")
        return 1
    sah, pesan = periksa(titik, akar, log)
    for baris in pesan:
        tulis(baris)
    tulis("Catatan: yang dibuktikan adalah keutuhan entri sampai titik periksa terakhir, diperiksa dengan kunci publik "
          "saja. Keaslian isi tiap entri tetap diperiksa dengan tools/verifikasi_audit.py (butuh NS_AUDIT_KEY).")
    return 0 if sah else 1


if __name__ == "__main__":
    sys.exit(main())
