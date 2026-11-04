# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
Uji titik periksa bertanda tangan Ed25519 dengan kunci yang berevolusi (Dokumentasi Teknis §2.9).

Masalah yang ditutup: HMAC memakai satu kunci untuk membuat sekaligus memeriksa. Penyerang yang membobol server
dan memegang NS_AUDIT_KEY bisa menulis ulang riwayat dengan sidik jari yang sah. Titik periksa menandatangani
kepala kedua buku (log audit dan Buku Rantai Bukti) dengan kunci Ed25519 periode itu; kunci periode berikutnya
disahkan di dalam titik periksa yang sama, lalu kunci lama dihapus. Auditor memeriksa hanya dengan sidik jari
kunci akar (publik), tanpa NS_AUDIT_KEY.
"""

import base64
import importlib.util
import io
import json
import os
import re
import secrets
import zlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.audit import LogAudit
from app.lapsit import buat_pdf
from app.titik_periksa import TitikPeriksa, kanonik_tanda_tangan, sha256_kumulatif

AKAR = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("verifikasi_titik_periksa", AKAR / "tools" / "verifikasi_titik_periksa.py")
alat = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(alat)

KUNCI_HMAC = "kunci-audit-uji-titik-periksa-0123456789abcdef"


@pytest.fixture
def sistem(tmp_path, monkeypatch):
    """Dua buku ASLI (kelas yang dipakai server) + titik periksa setiap 5 entri, semuanya di tmp_path."""
    monkeypatch.setenv("NS_AUDIT_KEY", KUNCI_HMAC)
    monkeypatch.setenv("NS_AUDIT_FILE", str(tmp_path / "audit_log.jsonl"))
    monkeypatch.setenv("NS_BUKTI_FILE", str(tmp_path / "rantai_bukti.jsonl"))
    monkeypatch.setenv("NS_TITIK_PERIKSA_FILE", str(tmp_path / "titik_periksa.jsonl"))
    monkeypatch.setenv("NS_TITIK_PERIKSA_KUNCI", str(tmp_path / "titik_periksa_kunci.json"))

    def nyalakan():
        log = LogAudit()
        bukti = LogAudit("NS_BUKTI_FILE", "data/rantai_bukti.jsonl", "buku rantai bukti")
        return log, bukti, TitikPeriksa({"audit_log": log, "rantai_bukti": bukti}, setiap=5)
    log, bukti, titik = nyalakan()
    return {"log": log, "bukti": bukti, "titik": titik, "dir": tmp_path, "nyalakan": nyalakan}


def isi(sistem, n_log=8, n_bukti=4):
    for i in range(n_log):
        sistem["log"].catat("operator", "SIMULASI_INSIDEN", {"langkah": i})
    for i in range(n_bukti):
        sistem["bukti"].catat("operator", "BUKTI_DIAMANKAN", {"nomor": f"BB-2026-{i + 1:03d}"})


def periksa(sistem, akar=None, tanpa_hmac=True, monkeypatch=None):
    d = sistem["dir"]
    if tanpa_hmac and monkeypatch:
        monkeypatch.delenv("NS_AUDIT_KEY", raising=False)     # auditor TIDAK memegang kunci HMAC
    keluar = io.StringIO()
    kode = alat.main(["--titik", str(d / "titik_periksa.jsonl"), "--akar", akar or sistem["titik"].sidik_jari_akar,
                      "--log", f"audit_log={d / 'audit_log.jsonl'}", "--log", f"rantai_bukti={d / 'rantai_bukti.jsonl'}"],
                     keluar=keluar)
    return kode, keluar.getvalue()


def catatan(berkas: Path) -> list[dict]:
    return [json.loads(b) for b in berkas.read_text(encoding="utf-8").splitlines() if b.strip()]


def tulis(berkas: Path, daftar: list[dict]) -> None:
    berkas.write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in daftar), encoding="utf-8")


# ---------------------------------------------------------------- Ed25519 murni di alat auditor
def test_ed25519_murni_sama_dengan_cryptography():
    """Alat auditor hanya memakai pustaka bawaan Python; hasilnya harus sama dengan pustaka cryptography."""
    for _ in range(12):
        sk = Ed25519PrivateKey.generate()
        pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        pesan = secrets.token_bytes(secrets.randbelow(200) + 1)
        ttd = sk.sign(pesan)
        assert alat.ed25519_sah(pk, pesan, ttd)
        assert not alat.ed25519_sah(pk, pesan + b"x", ttd)
        assert not alat.ed25519_sah(pk, pesan, ttd[:-1] + bytes([ttd[-1] ^ 1]))
        lain = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert not alat.ed25519_sah(lain, pesan, ttd)


def test_alat_auditor_tidak_mengimpor_pustaka_luar():
    sumber = (AKAR / "tools" / "verifikasi_titik_periksa.py").read_text(encoding="utf-8")
    impor = set(re.findall(r"^(?:from|import)\s+([a-zA-Z_]+)", sumber, re.M))
    assert impor <= {"__future__", "argparse", "hashlib", "json", "os", "sys", "pathlib"}, impor


# ---------------------------------------------------------------- server: akar, rotasi, penghapusan kunci
def test_mode_demo_tanpa_kunci_hmac_tidak_aktif(tmp_path, monkeypatch):
    monkeypatch.delenv("NS_AUDIT_KEY", raising=False)
    monkeypatch.setenv("NS_TITIK_PERIKSA_FILE", str(tmp_path / "t.jsonl"))
    monkeypatch.setenv("NS_TITIK_PERIKSA_KUNCI", str(tmp_path / "k.json"))
    log = LogAudit()
    t = TitikPeriksa({"audit_log": log}, setiap=1)
    log.catat("operator", "LOGIN", {})
    assert not t.aktif and t.buat("EKSPOR_LAPSIT") is None and list(tmp_path.iterdir()) == []


def test_akar_dibuat_sekali_dicatat_di_log_dan_berkas_kunci_600(sistem):
    t = sistem["titik"]
    assert t.aktif and re.fullmatch(r"[0-9a-f]{64}", t.sidik_jari_akar)
    akar = sistem["log"].cari("KUNCI_TITIK_PERIKSA_DIBUAT")
    assert len(akar) == 1 and akar[0]["detail"]["sidik_jari_akar"] == t.sidik_jari_akar
    assert (sistem["dir"] / "titik_periksa_kunci.json").stat().st_mode & 0o777 == 0o600
    isi(sistem)
    log2, _, t2 = sistem["nyalakan"]()                       # server menyala ulang: akar tidak berganti
    assert t2.aktif and t2.sidik_jari_akar == t.sidik_jari_akar
    assert len(log2.cari("KUNCI_TITIK_PERIKSA_DIBUAT")) == 1


def test_titik_periksa_berkala_dan_auditor_cukup_kunci_publik(sistem, monkeypatch):
    isi(sistem)                                              # 1 entri akar + 8 + 4 → setiap 5 entri
    daftar = catatan(sistem["dir"] / "titik_periksa.jsonl")
    assert len(daftar) == 2 and [c["no"] for c in daftar] == [1, 2]
    assert daftar[1]["kunci_publik"] == daftar[0]["kunci_publik_berikut"]
    kode, teks = periksa(sistem, monkeypatch=monkeypatch)
    assert kode == 0 and teks.count("[SAH]") == 2 and "[UTUH]" in teks, teks
    assert "belum dilindungi" in teks                         # 3 entri sesudah titik periksa terakhir disebut terus terang


def test_lapsit_memaksa_titik_periksa_dan_kepala_buku_sama_dengan_berkas(sistem):
    isi(sistem, 2, 1)
    c = sistem["titik"].buat("EKSPOR_LAPSIT")
    assert c["alasan"] == "EKSPOR_LAPSIT" and c["log"]["audit_log"]["jumlah"] == sistem["log"].jumlah
    assert c["log"]["audit_log"]["sha256_kumulatif"] == sha256_kumulatif(catatan(sistem["dir"] / "audit_log.jsonl"))


def test_entri_sebelum_titik_periksa_diubah_tertangkap(sistem, monkeypatch):
    isi(sistem)
    berkas = sistem["dir"] / "audit_log.jsonl"
    daftar = catatan(berkas)
    daftar[2]["detail"]["langkah"] = 99
    tulis(berkas, daftar)
    kode, teks = periksa(sistem, monkeypatch=monkeypatch)
    assert kode == 1 and "[RUSAK]" in teks and "titik periksa #1" in teks, teks


def test_log_dipotong_di_bawah_titik_periksa_tertangkap(sistem, monkeypatch):
    isi(sistem)
    berkas = sistem["dir"] / "audit_log.jsonl"               # titik periksa #2 mencatat 9 entri log audit
    tulis(berkas, catatan(berkas)[:6])
    kode, teks = periksa(sistem, monkeypatch=monkeypatch)
    assert kode == 1 and "dipotong" in teks, teks


def test_akar_salah_ditolak(sistem, monkeypatch):
    isi(sistem)
    kode, teks = periksa(sistem, akar="ab" * 32, monkeypatch=monkeypatch)
    assert kode == 1 and "akar" in teks.lower(), teks


def test_kunci_lama_dihapus_dari_disk(sistem):
    berkas_kunci = sistem["dir"] / "titik_periksa_kunci.json"
    lama = [json.loads(berkas_kunci.read_text())["kunci_privat"]]
    for _ in range(3):
        sistem["titik"].buat("UJI")
        lama.append(json.loads(berkas_kunci.read_text())["kunci_privat"])
    assert len(set(lama)) == 4
    semua = b"".join(p.read_bytes() for p in sistem["dir"].iterdir() if p.is_file())
    for k in lama[:-1]:                                       # hanya kunci periode berjalan yang masih ada
        assert k.encode() not in semua and bytes.fromhex(k) not in semua


def test_pencuri_kunci_terkini_tidak_bisa_menulis_ulang_masa_lalu(sistem, monkeypatch):
    """Penyerang memegang SEMUA rahasia server hari ini: NS_AUDIT_KEY dan kunci periode berjalan."""
    isi(sistem)
    d = sistem["dir"]
    sk_kini = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(json.loads((d / "titik_periksa_kunci.json").read_text())["kunci_privat"]))
    pk_kini = sk_kini.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    # 1. Tulis ulang entri #3 dan hitung ulang seluruh rantai HMAC (penyerang memegang NS_AUDIT_KEY).
    berkas = d / "audit_log.jsonl"
    daftar = catatan(berkas)
    palsu = LogAudit.__new__(LogAudit)
    palsu._kunci = KUNCI_HMAC.encode()
    sebelumnya = "0" * 64
    for e in daftar:
        if e["urutan"] == 3:
            e["detail"]["langkah"] = 99
        e["hash_sebelumnya"] = sebelumnya
        e["hash"] = palsu._sidik_jari(e)
        sebelumnya = e["hash"]
    tulis(berkas, daftar)

    # 2a. Tanda tangani ulang titik periksa lama dengan kunci curian, kunci publik dibiarkan → tanda tangan tidak sah.
    tp = d / "titik_periksa.jsonl"
    asli = catatan(tp)
    ubah = [dict(c) for c in asli]
    for c in ubah:
        c["log"] = json.loads(json.dumps(c["log"]))
        n = c["log"]["audit_log"]["jumlah"]
        c["log"]["audit_log"]["sha256_kumulatif"] = sha256_kumulatif(daftar[:n])
        c["tanda_tangan"] = sk_kini.sign(kanonik_tanda_tangan(c)).hex()
    tulis(tp, ubah)
    kode, teks = periksa(sistem, monkeypatch=monkeypatch)
    assert kode == 1 and "tanda tangan" in teks.lower(), teks

    # 2b. Rantai baru yang berakar di kunci curian → akarnya tidak sama dengan berita acara.
    for c in ubah:
        c["kunci_publik"] = c["kunci_publik_berikut"] = pk_kini
        c["tanda_tangan"] = sk_kini.sign(kanonik_tanda_tangan(c)).hex()
    tulis(tp, ubah)
    kode, teks = periksa(sistem, monkeypatch=monkeypatch)
    assert kode == 1 and "akar" in teks.lower(), teks


def test_status_kunci_tertinggal_tidak_diam_diam_membuat_akar_baru(sistem, capsys):
    isi(sistem)
    tp = sistem["dir"] / "titik_periksa.jsonl"
    tulis(tp, catatan(tp)[:-1])                               # titik periksa terakhir hilang (rusak/disunting)
    _, _, t2 = sistem["nyalakan"]()
    assert not t2.aktif and "tidak sesuai" in t2.galat
    assert t2.buat("EKSPOR_LAPSIT") is None


def teks_pdf(pdf: bytes) -> str:
    hasil = []
    for aliran in re.findall(rb"stream\r?\n(.*?)endstream", pdf, re.S):
        data = aliran.strip()
        if data.endswith(b"~>"):
            data = base64.a85decode(data[:-2])
        try:
            isi_ = zlib.decompress(data).decode("latin-1")
        except zlib.error:
            continue
        hasil += [re.sub(r"\\([()\\])", r"\1", s) for s in re.findall(r"\(((?:\\.|[^\\)])*)\) Tj", isi_)]
    return " ".join(hasil)


def test_lapsit_mencetak_sidik_jari_akar_dan_nomor_titik_periksa(sistem):
    c = sistem["titik"].buat("EKSPOR_LAPSIT")
    hasil = sistem["log"].verifikasi()
    teks = teks_pdf(buat_pdf([], hasil, "operator", [], None, titik=sistem["titik"].ringkasan(c)))
    assert sistem["titik"].sidik_jari_akar in teks.replace(" ", "") and "titik periksa #1" in teks.lower()


def test_titik_periksa_lanjutan_diganti_kunci_curian_tertangkap(sistem, monkeypatch):
    """Titik periksa #1 dibiarkan asli; entri yang hanya dilindungi #2 diubah, lalu #2 ditandatangani ulang
    dengan kunci curian. Kunci itu tidak pernah disahkan oleh #1, jadi harus ditolak."""
    isi(sistem)
    d = sistem["dir"]
    sk_kini = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(json.loads((d / "titik_periksa_kunci.json").read_text())["kunci_privat"]))
    berkas = d / "audit_log.jsonl"
    daftar = catatan(berkas)
    daftar[7]["detail"]["langkah"] = 99                      # entri #8: di luar cakupan titik periksa #1 (5 entri)
    tulis(berkas, daftar)
    tp = d / "titik_periksa.jsonl"
    asli = catatan(tp)
    c = json.loads(json.dumps(asli[1]))
    c["log"]["audit_log"]["sha256_kumulatif"] = sha256_kumulatif(daftar[:c["log"]["audit_log"]["jumlah"]])
    c["kunci_publik"] = sk_kini.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    c["tanda_tangan"] = sk_kini.sign(kanonik_tanda_tangan(c)).hex()
    tulis(tp, [asli[0], c])
    kode, teks = periksa(sistem, monkeypatch=monkeypatch)
    assert kode == 1 and "disahkan" in teks, teks


def test_buku_yang_belum_berisi_tidak_menggagalkan_auditor(tmp_path, monkeypatch):
    """Pemasangan baru: Buku Rantai Bukti belum punya entri, jadi berkasnya belum ada. Titik periksa mencatatnya
    dengan 0 entri; alat auditor harus menerimanya, termasuk dengan susunan berkas bawaan (data/ di folder kerja)."""
    monkeypatch.setenv("NS_AUDIT_KEY", KUNCI_HMAC)
    monkeypatch.chdir(tmp_path)
    for v in ("NS_AUDIT_FILE", "NS_BUKTI_FILE", "NS_TITIK_PERIKSA_FILE", "NS_TITIK_PERIKSA_KUNCI"):
        monkeypatch.delenv(v, raising=False)
    log = LogAudit()
    bukti = LogAudit("NS_BUKTI_FILE", "data/rantai_bukti.jsonl", "buku rantai bukti")
    t = TitikPeriksa({"audit_log": log, "rantai_bukti": bukti}, setiap=5)
    log.catat("operator", "EKSPOR_LAPSIT", {})
    assert t.buat("EKSPOR_LAPSIT")["log"]["rantai_bukti"]["jumlah"] == 0
    assert not (tmp_path / "data" / "rantai_bukti.jsonl").exists()
    monkeypatch.delenv("NS_AUDIT_KEY")
    for argv in (["--akar", t.sidik_jari_akar], ["--akar", t.sidik_jari_akar, "--log", "audit_log=data/audit_log.jsonl"]):
        keluar = io.StringIO()
        kode = alat.main(argv, keluar=keluar)
        assert kode == 0 and "[SAH]" in keluar.getvalue() and "rantai_bukti: 0 entri" in keluar.getvalue(), keluar.getvalue()
    # Buku yang SUDAH berisi tetapi berkasnya tidak diberikan tetap ditolak.
    bukti.catat("operator", "BUKTI_DIAMANKAN", {"nomor": "BB-2026-001"})
    t.buat("UJI")
    keluar = io.StringIO()
    assert alat.main(["--akar", t.sidik_jari_akar, "--log", "audit_log=data/audit_log.jsonl"], keluar=keluar) == 1
    assert "tidak diberikan" in keluar.getvalue()
