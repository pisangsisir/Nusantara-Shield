#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
Saksi Berjenjang Luring — alat untuk SATUAN ATASAN (mis. Sansidam), dijalankan di komputer satuan itu sendiri.

Masalah yang ditutup: penyerang yang menguasai server posko bisa mengembalikan log DAN berkas titik periksa ke keadaan
lama. Hasilnya tetap sah secara kriptografi. Yang bisa menangkapnya hanya salinan yang disimpan di LUAR posko.
Alat ini membuat penyimpanan itu tertib dan bisa diperiksa, berjenjang:

  posko ──Berkas Saksi──▶ satuan atasan (Buku Saksi + Tanda Terima) ──Rekap Saksi──▶ jenjang di atasnya ──▶ …

Setiap jenjang memegang kunci Ed25519 sendiri. Setiap berkas yang diterima diperiksa, dibandingkan dengan kiriman
sebelumnya dari pengirim yang sama, lalu dicatat di Buku Saksi: entri bernomor, berantai SHA-256, dan bertanda tangan
kunci jenjang itu. Aturan pembandingnya satu untuk semua jenjang:
  - kiriman baru harus MEMUAT seluruh isi kiriman lama, sama persis (titik periksa posko, atau entri Buku Saksi
    jenjang di bawah);
  - lebih pendek = riwayat digulung mundur → DITOLAK; isi lama berbeda = riwayat bercabang → DITOLAK.
Jenjang atas yang memegang rekap jenjang bawah juga menangkap bila jenjang bawah sendiri menulis ulang Buku Saksinya.

Perintah (direktori --dir berisi kunci dan Buku Saksi jenjang ini; simpan di media yang dijaga):
    python3 tools/saksi.py kunci   --dir SAKSI --label "Sansidam Jaya"
    python3 tools/saksi.py terima  SAKSI-NusantaraShield-titik12-....json --dir SAKSI [--harap <sidik jari>]
    python3 tools/saksi.py status  --dir SAKSI
    python3 tools/saksi.py rekap   --dir SAKSI --keluar rekap-sansidam.json
    python3 tools/saksi.py periksa-tanda-terima tanda-terima-....json --kunci <sidik jari kunci atasan>

Di posko, auditor memakai saksi yang dipegang atasan:
    python3 tools/verifikasi_titik_periksa.py --akar <sidik jari akar> --saksi <berkas saksi dari arsip atasan>

Kode keluar: 0 = sah dan tercatat, 1 = ditolak/rusak, 2 = tidak bisa memeriksa (berkas atau kunci tidak ada).

Batas yang jujur:
  - Kunci jenjang disimpan tanpa sandi (izin 600). Simpan direktori --dir di komputer luring yang dijaga, atau di media
    terenkripsi. Tanda tangan dibuat dengan Python murni, tidak tahan serangan kanal samping (waktu); itu wajar di
    komputer luring satuan, tidak untuk mesin bersama.
  - Kiriman PERTAMA dari pengirim baru dipercaya apa adanya (sidik jarinya dicetak [BARU]); cocokkan dengan berita acara
    atau pakai --harap.
  - Alat ini tidak menyalurkan berkas; penyerahan lewat media fisik dan jadwalnya diatur prosedur satuan.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

# Pemeriksa Ed25519 dan rantai titik periksa diambil dari alat auditor (satu implementasi, sudah diuji terhadap
# pustaka cryptography). Dimuat lewat path agar tetap jalan dengan `python3 -I`.
_spec = importlib.util.spec_from_file_location("_vtp", Path(__file__).resolve().with_name("verifikasi_titik_periksa.py"))
vtp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vtp)

DOMAIN_BUKU = b"nusantara-shield/buku-saksi/1\n"
JENIS_SAKSI = vtp.JENIS_SAKSI
JENIS_REKAP = "nusantara-shield/rekap-saksi/1"
JENIS_TANDA_TERIMA = "nusantara-shield/tanda-terima-saksi/1"
NOL = "0" * 64
MAKS_BERKAS = 64 * 1024 * 1024          # ±90.000 titik periksa; berkas lebih besar ditolak sebelum dibaca


def bersihkan_label(nilai) -> str:
    """Label dari pengirim tidak dipercaya: buang karakter kendali dan format (ESC, CR, LF, arah teks, surrogate)
    agar tidak bisa menimpa atau menyembunyikan baris [BARU]/[RUSAK] di terminal."""
    teks = "".join(ch for ch in str(nilai) if unicodedata.category(ch) not in ("Cc", "Cf", "Cs", "Co", "Cn"))
    return " ".join(teks.split())[:80] or "(tanpa nama)"


class Galat(Exception):
    """Tidak bisa memeriksa (kode 2)."""


class Ditolak(Exception):
    """Berkas tidak sah atau riwayat mundur/bercabang (kode 1)."""


# ---------------------------------------------------------------- Ed25519 (RFC 8032 §5.1.6, penandatangan)
def _enkode(titik) -> bytes:
    zi = pow(titik[2], vtp._P - 2, vtp._P)
    x, y = titik[0] * zi % vtp._P, titik[1] * zi % vtp._P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _rahasia(benih: bytes) -> tuple[int, bytes]:
    h = hashlib.sha512(benih).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def publik_dari_benih(benih: bytes) -> bytes:
    return _enkode(vtp._kali(_rahasia(benih)[0], vtp._G))


def tandatangani(benih: bytes, pesan: bytes) -> bytes:
    a, awalan = _rahasia(benih)
    A = _enkode(vtp._kali(a, vtp._G))
    r = int.from_bytes(hashlib.sha512(awalan + pesan).digest(), "little") % vtp._Q
    R = _enkode(vtp._kali(r, vtp._G))
    k = int.from_bytes(hashlib.sha512(R + A + pesan).digest(), "little") % vtp._Q
    return R + ((r + k * a) % vtp._Q).to_bytes(32, "little")


# ---------------------------------------------------------------- Buku Saksi
kanonik = vtp.kanonik


def sidik_jari_kunci(publik_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(publik_hex)).hexdigest()


def pesan_entri(e: dict) -> bytes:
    return DOMAIN_BUKU + kanonik({k: v for k, v in e.items() if k != "tanda_tangan"})


def periksa_buku(entri: list, publik_hex: str | None = None) -> str | None:
    """Buku Saksi (milik sendiri atau isi rekap jenjang bawah): nomor, rantai, satu kunci, tanda tangan."""
    if not isinstance(entri, list):
        return "daftar entri Buku Saksi tidak ada"
    sebelumnya = NOL
    for i, e in enumerate(entri, start=1):
        if not isinstance(e, dict) or e.get("no") != i:
            return f"nomor entri #{i} loncat"
        if e.get("sebelumnya") != sebelumnya:
            return f"rantai putus di entri #{i}"
        pk = e.get("kunci_publik")
        if publik_hex is None:
            publik_hex = pk
        if pk != publik_hex:
            return f"entri #{i} ditandatangani kunci lain"
        try:
            sah = vtp.ed25519_sah(bytes.fromhex(pk), pesan_entri(e), bytes.fromhex(e.get("tanda_tangan", "")))
        except (TypeError, ValueError):
            sah = False
        if not sah:
            return f"tanda tangan entri #{i} tidak sah (isi diubah sesudah ditandatangani)"
        sebelumnya = hashlib.sha256(kanonik(e)).hexdigest()
    return None


def _fsync_dir(d: Path) -> None:
    try:
        fd = os.open(d, os.O_RDONLY)
    except OSError:
        return                                   # Windows: direktori tidak bisa dibuka; os.replace sudah atomik
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _tulis_atomik(berkas: Path, isi: bytes | str, izin: int = 0o644) -> None:
    """Bita ditulis apa adanya (tanpa terjemahan baris baru), lalu diganti secara atomik dan direktorinya di-fsync."""
    data = isi.encode("utf-8") if isinstance(isi, str) else isi
    sementara = berkas.with_name(berkas.name + ".baru")
    fd = os.open(sementara, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), izin)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(sementara, berkas)
    _fsync_dir(berkas.parent)


def _nama_arsip(entri: dict) -> str:
    """Satu berkas per kiriman yang tercatat; nama memuat sidik jari berkas, jadi tidak pernah saling menimpa."""
    return f"{entri['jenis']}-{entri['nomor']:06d}-{entri['sha256_berkas'][:16]}.json"


class Jenjang:
    """Satu direktori = satu jenjang: kunci, Buku Saksi, arsip kiriman terakhir per pengirim."""

    def __init__(self, direktori: str | Path) -> None:
        self.dir = Path(direktori)
        self.berkas_kunci = self.dir / "kunci_saksi.json"
        self.berkas_buku = self.dir / "buku_saksi.jsonl"
        self.arsip = self.dir / "arsip"

    # -- kunci
    def buat_kunci(self, label: str) -> str:
        if self.berkas_kunci.exists():
            raise Galat(f"{self.berkas_kunci} sudah ada; kunci jenjang tidak pernah ditimpa.")
        self.dir.mkdir(parents=True, exist_ok=True)
        benih = os.urandom(32)
        _tulis_atomik(self.berkas_kunci, json.dumps({"versi_format": 1, "label": bersihkan_label(label), "benih": benih.hex()}), 0o600)
        os.chmod(self.berkas_kunci, 0o600)
        return hashlib.sha256(publik_dari_benih(benih)).hexdigest()

    def kunci(self) -> tuple[bytes, str, str]:
        if not self.berkas_kunci.exists():
            raise Galat(f"Kunci jenjang belum dibuat: jalankan dulu `saksi.py kunci --dir {self.dir} --label ...`.")
        d = json.loads(self.berkas_kunci.read_text(encoding="utf-8"))
        benih = bytes.fromhex(d["benih"])
        return benih, publik_dari_benih(benih).hex(), d.get("label", "")

    # -- buku
    def buku(self) -> list[dict]:
        if not self.berkas_buku.exists():
            return []
        entri = []
        for no, baris in enumerate(self.berkas_buku.read_text(encoding="utf-8").splitlines(), start=1):
            if baris.strip():
                try:
                    entri.append(json.loads(baris))
                except (ValueError, RecursionError):
                    raise Ditolak(f"[RUSAK] Buku Saksi baris {no} bukan JSON yang sah (mungkin terpotong saat komputer "
                                  "mati di tengah pencatatan). Tidak ada yang dicatat. Bila itu baris TERAKHIR dan "
                                  "terpotong, salin bukunya sebagai cadangan, hapus baris itu saja, lalu ulangi.")
        _, pk, _ = self.kunci()
        if rusak := periksa_buku(entri, pk):
            raise Ditolak(f"[RUSAK] Buku Saksi jenjang ini sendiri rusak: {rusak}. Tidak ada yang dicatat; "
                          "periksa media penyimpanan dan bandingkan dengan rekap yang pernah dikirim ke atas.")
        return entri

    def _dasar(self, identitas: str, buku: list[dict]) -> dict | None:
        """Kiriman terakhir yang SAH dari pengirim ini. Patokannya Buku Saksi (bertanda tangan), bukan berkas arsip:
        arsip hanya dipakai bila sidik jari berkasnya sama dengan yang tercatat di entri buku terakhir pengirim itu."""
        tercatat = next((e for e in reversed(buku) if e.get("pengirim", {}).get("identitas") == identitas), None)
        f = self.arsip / identitas / "terakhir.json"
        mentah = f.read_bytes() if f.exists() else None
        if tercatat is None:
            # Arsip tanpa entri buku hanya mungkin bila komputer mati di antara keduanya: arsip lebih baru, jadi lebih ketat.
            return json.loads(mentah) if mentah is not None else None
        if mentah is None or hashlib.sha256(mentah).hexdigest() != tercatat["sha256_berkas"]:
            # Arsip lebih baru karena terhenti di tengah pencatatan juga diterima bila memuat kiriman yang tercatat.
            simpan = self.arsip / identitas / _nama_arsip(tercatat)
            cadangan = simpan.read_bytes() if simpan.exists() else None
            if cadangan is None or hashlib.sha256(cadangan).hexdigest() != tercatat["sha256_berkas"]:
                raise Galat(f"Arsip kiriman '{tercatat['pengirim']['label']}' tidak cocok dengan Buku Saksi entri "
                            f"#{tercatat['no']} (hilang atau ditukar). Tidak ada yang dicatat. Pulihkan folder "
                            f"{self.arsip / identitas} dari cadangan; jangan dihapus, karena tanpa arsip kiriman "
                            "mundur tidak bisa dibandingkan.")
            mentah = cadangan
        dasar = json.loads(mentah)
        urutan = dasar.get("titik_periksa") if dasar.get("jenis") == JENIS_SAKSI else dasar.get("buku")
        if not isinstance(urutan, list) or len(urutan) != tercatat["nomor"]:
            raise Galat(f"Arsip kiriman '{tercatat['pengirim']['label']}' tidak sesuai jumlah yang tercatat di Buku Saksi.")
        return dasar

    # -- menerima kiriman
    def terima(self, mentah: bytes, harap: str | None = None) -> tuple[dict, list[str]]:
        benih, pk, label_saya = self.kunci()
        buku = self.buku()
        try:
            kiriman = json.loads(mentah.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise Ditolak("[RUSAK] Berkas bukan JSON yang sah.")
        if not isinstance(kiriman, dict):
            raise Ditolak("[RUSAK] Berkas bukan Berkas Saksi atau Rekap Saksi Nusantara Shield.")
        pesan: list[str] = []
        jenis = kiriman.get("jenis")
        if jenis == JENIS_SAKSI:
            urutan, identitas = kiriman.get("titik_periksa"), str(kiriman.get("sidik_jari_akar", "")).lower()
            if not isinstance(urutan, list):
                raise Ditolak("[RUSAK] Berkas Saksi tidak memuat daftar titik periksa.")
            if rusak := vtp.periksa_rantai(urutan, identitas):
                raise Ditolak(rusak)
            label, satuan = bersihkan_label(kiriman.get("posko", "posko")), "titik periksa"
        elif jenis == JENIS_REKAP:
            urutan, pk_bawah = kiriman.get("buku"), str(kiriman.get("kunci_publik", ""))
            try:
                identitas = sidik_jari_kunci(pk_bawah)
            except ValueError:
                raise Ditolak("[RUSAK] Rekap Saksi tidak memuat kunci publik yang sah.")
            if rusak := periksa_buku(urutan, pk_bawah):
                raise Ditolak(f"[RUSAK] Rekap Saksi tidak sah: {rusak}.")
            if identitas == sidik_jari_kunci(pk):
                raise Ditolak("[RUSAK] Rekap ini milik jenjang ini sendiri; rekap dikirim ke jenjang di atasnya.")
            label, satuan = bersihkan_label(kiriman.get("label", "satuan")), "entri Buku Saksi"
        else:
            raise Ditolak("[RUSAK] Berkas bukan Berkas Saksi atau Rekap Saksi Nusantara Shield.")
        if not urutan:
            raise Ditolak(f"[RUSAK] Kiriman kosong: tidak ada {satuan}.")

        if harap and harap.strip().lower() != identitas:
            raise Ditolak(f"[RUSAK] Sidik jari pengirim {identitas} tidak sama dengan yang diharapkan ({harap}).")
        lama = self._dasar(identitas, buku)
        if lama is None:
            kembar = next((e for e in buku if e["pengirim"]["label"] == label), None)
            if kembar and not harap:
                raise Ditolak(f"[RUSAK] Nama '{label}' sudah tercatat dengan sidik jari lain "
                              f"({kembar['pengirim']['identitas'][:16]}…), kini datang dengan {identitas[:16]}…. Akar atau "
                              "kunci yang berganti bisa berarti riwayat dibuat ulang dari nol. Tidak dicatat; terima hanya "
                              "dengan --harap <sidik jari baru> setelah dicocokkan dengan berita acara.")
            pesan.append(f"[BARU]  Pengirim baru '{label}'. Cocokkan sidik jarinya dengan berita acara: {identitas}")
        else:
            urutan_lama = lama["titik_periksa"] if lama.get("jenis") == JENIS_SAKSI else lama["buku"]
            if len(urutan) < len(urutan_lama):
                raise Ditolak(f"[RUSAK] Riwayat digulung mundur: kiriman sebelumnya dari '{label}' memuat {satuan} sampai "
                              f"#{len(urutan_lama)}, kiriman ini hanya sampai #{len(urutan)}. Tidak dicatat.")
            for i, (a, b) in enumerate(zip(urutan, urutan_lama), start=1):
                if kanonik(a) != kanonik(b):
                    raise Ditolak(f"[RUSAK] Riwayat bercabang: {satuan} #{i} dari '{label}' berbeda dengan kiriman "
                                  "sebelumnya, padahal keduanya bertanda tangan sah. Tidak dicatat; laporkan ke jenjang "
                                  "di atas.")
            baru = len(urutan) - len(urutan_lama)
            pesan.append(f"[MAJU]  '{label}': {satuan} #{len(urutan_lama)} → #{len(urutan)} "
                         + (f"({baru} baru); isi lama sama persis." if baru else "(tidak ada yang baru); isi lama sama persis."))

        entri = {"no": len(buku) + 1,
                 "waktu_terima": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 "jenis": "saksi_posko" if jenis == JENIS_SAKSI else "rekap_satuan",
                 "pengirim": {"label": label, "identitas": identitas},
                 "nomor": len(urutan),
                 "sha256_terakhir": hashlib.sha256(kanonik(urutan[-1])).hexdigest(),
                 "sha256_berkas": hashlib.sha256(mentah).hexdigest(),
                 "sebelumnya": hashlib.sha256(kanonik(buku[-1])).hexdigest() if buku else NOL,
                 "kunci_publik": pk}
        entri["tanda_tangan"] = tandatangani(benih, pesan_entri(entri)).hex()

        # Urutan tulis: arsip kiriman dulu, baru Buku Saksi (buku tidak pernah merujuk kiriman yang tidak tersimpan).
        d = self.arsip / identitas
        d.mkdir(parents=True, exist_ok=True)
        _tulis_atomik(d / _nama_arsip(entri), mentah)
        _tulis_atomik(d / "terakhir.json", mentah)
        with self.berkas_buku.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entri, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())
        _fsync_dir(self.dir)
        tanda_terima = {"jenis": JENIS_TANDA_TERIMA, "penerima": label_saya, "entri": entri}
        pesan.append(f"[TERCATAT] Buku Saksi entri #{entri['no']} · {entri['waktu_terima']} · {satuan} #{len(urutan)}")
        return tanda_terima, pesan

    def rekap(self) -> dict:
        _, pk, label = self.kunci()
        buku = self.buku()
        if not buku:
            raise Galat("Buku Saksi masih kosong; belum ada yang bisa direkap.")
        return {"jenis": JENIS_REKAP, "label": label, "kunci_publik": pk,
                "dibuat": datetime.now(timezone.utc).isoformat(timespec="seconds"), "buku": buku}

    def status(self) -> list[dict]:
        terakhir: dict[str, dict] = {}
        for e in self.buku():
            terakhir[e["pengirim"]["identitas"]] = e
        return sorted(terakhir.values(), key=lambda e: e["waktu_terima"])


def periksa_tanda_terima(tt: dict, kunci: str) -> str | None:
    if not isinstance(tt, dict) or tt.get("jenis") != JENIS_TANDA_TERIMA or not isinstance(tt.get("entri"), dict):
        return "berkas bukan Tanda Terima Saksi Nusantara Shield"
    e = tt["entri"]
    try:
        if sidik_jari_kunci(e.get("kunci_publik", "")) != kunci.strip().lower():
            return "Tanda Terima ditandatangani kunci lain, bukan kunci satuan atasan yang diharapkan"
        sah = vtp.ed25519_sah(bytes.fromhex(e["kunci_publik"]), pesan_entri(e), bytes.fromhex(e.get("tanda_tangan", "")))
    except (KeyError, TypeError, ValueError):
        sah = False
    return None if sah else "tanda tangan Tanda Terima tidak sah (isi diubah sesudah ditandatangani)"


# ---------------------------------------------------------------- CLI
def main(argv: list[str] | None = None, keluar=sys.stdout) -> int:
    p = argparse.ArgumentParser(prog="saksi.py", description="Saksi Berjenjang Luring untuk satuan atasan.")
    sub = p.add_subparsers(dest="perintah", required=True)
    k = sub.add_parser("kunci", help="buat kunci Ed25519 jenjang ini (sekali)")
    k.add_argument("--dir", required=True)
    k.add_argument("--label", required=True, help="nama satuan, mis. 'Sansidam Jaya'")
    t = sub.add_parser("terima", help="periksa dan catat Berkas Saksi posko atau Rekap Saksi jenjang bawah")
    t.add_argument("berkas")
    t.add_argument("--dir", required=True)
    t.add_argument("--harap", help="sidik jari pengirim dari berita acara (akar posko atau kunci jenjang bawah)")
    t.add_argument("--tanda-terima", help="tempat menulis Tanda Terima (bawaan: di samping berkas kiriman)")
    s = sub.add_parser("status", help="kiriman terakhir per pengirim")
    s.add_argument("--dir", required=True)
    r = sub.add_parser("rekap", help="rekap Buku Saksi untuk jenjang di atas")
    r.add_argument("--dir", required=True)
    r.add_argument("--keluar", required=True)
    q = sub.add_parser("periksa-tanda-terima", help="periksa Tanda Terima dari satuan atasan")
    q.add_argument("berkas")
    q.add_argument("--kunci", required=True, help="sidik jari kunci satuan atasan (64 heksadesimal)")
    a = p.parse_args(argv)
    tulis = lambda teks="": print(teks, file=keluar)
    try:
        if a.perintah == "kunci":
            sj = Jenjang(a.dir).buat_kunci(a.label)
            tulis(f"[SIAP]  Kunci jenjang '{a.label}' dibuat di {Path(a.dir) / 'kunci_saksi.json'} (izin 600).")
            tulis(f"        Sidik jari kunci (catat di berita acara, serahkan ke posko dan jenjang di atas): {sj}")
        elif a.perintah == "terima":
            sumber = Path(a.berkas)
            if not sumber.is_file():
                raise Galat(f"berkas tidak ditemukan: {sumber}")
            if sumber.stat().st_size > MAKS_BERKAS:
                raise Ditolak(f"[RUSAK] Berkas lebih dari {MAKS_BERKAS // 2**20} MB; bukan kiriman yang wajar.")
            tt, pesan = Jenjang(a.dir).terima(sumber.read_bytes(), a.harap)
            tujuan = Path(a.tanda_terima) if a.tanda_terima else sumber.with_name(
                f"TANDA-TERIMA-{sumber.stem}.json")
            tujuan.write_text(json.dumps(tt, ensure_ascii=False, indent=1), encoding="utf-8")
            for b in pesan:
                tulis(b)
            tulis(f"[TANDA TERIMA] {tujuan} · kode {tt['entri']['tanda_tangan'][:16]}")
        elif a.perintah == "status":
            daftar = Jenjang(a.dir).status()
            if not daftar:
                tulis("Buku Saksi masih kosong.")
            sekarang = datetime.now(timezone.utc)
            for e in daftar:
                umur = (sekarang - datetime.fromisoformat(e["waktu_terima"])).days
                tulis(f"{bersihkan_label(e['pengirim']['label'])[:32]:<32} {e['jenis']:<13} #{e['nomor']:<6} {e['waktu_terima']} "
                      f"({umur} hari lalu) · {e['pengirim']['identitas'][:16]}…")
        elif a.perintah == "rekap":
            rekap = Jenjang(a.dir).rekap()
            Path(a.keluar).write_text(json.dumps(rekap, ensure_ascii=False, indent=1), encoding="utf-8")
            tulis(f"[SIAP]  Rekap Saksi {len(rekap['buku'])} entri → {a.keluar}")
            tulis(f"        Sidik jari kunci jenjang ini: {sidik_jari_kunci(rekap['kunci_publik'])}")
        else:
            sumber = Path(a.berkas)
            if not sumber.is_file():
                raise Galat(f"berkas tidak ditemukan: {sumber}")
            try:
                tt = json.loads(sumber.read_text(encoding="utf-8"))
            except (ValueError, RecursionError):
                tt = None
            if rusak := periksa_tanda_terima(tt, a.kunci):
                raise Ditolak(f"[RUSAK] {rusak}.")
            e = tt["entri"]
            tulis(f"[SAH]   Tanda Terima dari '{bersihkan_label(tt.get('penerima'))}': Buku Saksi entri #{e['no']} · "
                  f"{bersihkan_label(e['waktu_terima'])} · {bersihkan_label(e['pengirim']['label'])} #{e['nomor']}")
    except Galat as e:
        tulis(f"GAGAL: {e}")
        return 2
    except Ditolak as e:
        tulis(str(e))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
