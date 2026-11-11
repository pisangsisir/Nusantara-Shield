# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
Uji Saksi Berjenjang Luring (tools/saksi.py, POST /api/saksi, verifikasi_titik_periksa.py --saksi).

Masalah yang ditutup: penyerang yang menguasai server posko mengembalikan log DAN berkas titik periksa ke keadaan
lama; hasilnya tetap sah secara kriptografi. Yang menangkapnya hanya salinan di luar posko. Posko menyerahkan Berkas
Saksi ke satuan atasan; satuan atasan mencatatnya di Buku Saksi bertanda tangan kuncinya sendiri dan merekapnya ke
jenjang di atas. Setiap jenjang menolak kiriman yang lebih pendek (digulung mundur) atau yang isi lamanya berbeda
(bercabang), termasuk Buku Saksi jenjang bawah yang ditulis ulang pemiliknya sendiri.
"""

import importlib.util
import io
import json
import os
import re
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from app import main
from app.audit import LogAudit
from app.keamanan import PEMBATAS
from app.titik_periksa import JENIS_SAKSI, TitikPeriksa, kanonik_tanda_tangan

AKAR = Path(__file__).resolve().parent.parent


def _muat(nama):
    spec = importlib.util.spec_from_file_location(nama, AKAR / "tools" / f"{nama}.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


saksi = _muat("saksi")
vtp = _muat("verifikasi_titik_periksa")


@pytest.fixture
def posko(tmp_path, monkeypatch):
    """Posko dengan dua buku ASLI dan titik periksa setiap 5 entri (kelas yang dipakai server)."""
    d = tmp_path / "posko"
    d.mkdir()
    monkeypatch.setenv("NS_AUDIT_KEY", "kunci-audit-uji-saksi-0123456789abcdef")
    monkeypatch.setenv("NS_AUDIT_FILE", str(d / "audit_log.jsonl"))
    monkeypatch.setenv("NS_BUKTI_FILE", str(d / "rantai_bukti.jsonl"))
    monkeypatch.setenv("NS_TITIK_PERIKSA_FILE", str(d / "titik_periksa.jsonl"))
    monkeypatch.setenv("NS_TITIK_PERIKSA_KUNCI", str(d / "titik_periksa_kunci.json"))
    log = LogAudit()
    bukti = LogAudit("NS_BUKTI_FILE", "data/rantai_bukti.jsonl", "buku rantai bukti")
    titik = TitikPeriksa({"audit_log": log, "rantai_bukti": bukti}, setiap=5)
    return {"dir": d, "log": log, "bukti": bukti, "titik": titik, "tmp": tmp_path}


def isi(p, n=6):
    for i in range(n):
        p["log"].catat("operator", "SIMULASI_INSIDEN", {"langkah": i})


def ekspor(p, nama="saksi.json") -> Path:
    berkas = p["tmp"] / nama
    berkas.write_text(json.dumps(p["titik"].berkas_saksi("Posko RS Uji", "uji"), ensure_ascii=False), encoding="utf-8")
    return berkas


def jalankan(modul, *arg):
    keluar = io.StringIO()
    return modul.main([str(a) for a in arg], keluar=keluar), keluar.getvalue()


def jenjang(tmp, nama, label):
    d = tmp / nama
    kode, teks = jalankan(saksi, "kunci", "--dir", d, "--label", label)
    assert kode == 0, teks
    return d, re.search(r"[0-9a-f]{64}", teks).group()


def auditor(p, berkas_saksi, monkeypatch):
    monkeypatch.delenv("NS_AUDIT_KEY", raising=False)
    d = p["dir"]
    return jalankan(vtp, "--akar", p["titik"].sidik_jari_akar, "--titik", d / "titik_periksa.jsonl",
                    "--log", f"audit_log={d / 'audit_log.jsonl'}", "--log", f"rantai_bukti={d / 'rantai_bukti.jsonl'}",
                    "--saksi", berkas_saksi)


# ---------------------------------------------------------------- dasar: kunci dan tanda tangan
def test_tanda_tangan_python_murni_sama_dengan_cryptography():
    for i in range(8):
        benih = os.urandom(32)
        pesan = os.urandom(i * 13 + 1)
        sk = Ed25519PrivateKey.from_private_bytes(benih)
        assert saksi.publik_dari_benih(benih) == sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert saksi.tandatangani(benih, pesan) == sk.sign(pesan)


def test_alat_atasan_hanya_pustaka_bawaan():
    sumber = (AKAR / "tools" / "saksi.py").read_text(encoding="utf-8")
    impor = set(re.findall(r"^(?:from|import)\s+([a-zA-Z_.]+)", sumber, re.M))
    assert impor <= {"__future__", "argparse", "hashlib", "importlib.util", "json", "os", "sys", "datetime", "pathlib"}, impor


def test_kunci_jenjang_izin_600_dan_tidak_pernah_ditimpa(tmp_path):
    d, sj = jenjang(tmp_path, "atasan", "Sansidam Uji")
    assert stat.S_IMODE((d / "kunci_saksi.json").stat().st_mode) == 0o600
    kode, teks = jalankan(saksi, "kunci", "--dir", d, "--label", "Lain")
    assert kode == 2 and "tidak pernah ditimpa" in teks
    _, pk, _ = saksi.Jenjang(d).kunci()
    assert saksi.sidik_jari_kunci(pk) == sj


# ---------------------------------------------------------------- posko → satuan atasan
def test_saksi_posko_diterima_dicatat_dan_tanda_terima_sah(posko, tmp_path):
    isi(posko)
    berkas = ekspor(posko)
    j = json.loads(berkas.read_text())
    assert j["jenis"] == JENIS_SAKSI and j["sidik_jari_akar"] == posko["titik"].sidik_jari_akar
    assert j["titik_periksa"][-1]["alasan"] == "SAKSI" and j["titik_terakhir"] == len(j["titik_periksa"])
    d, sj = jenjang(tmp_path, "atasan", "Sansidam Uji")
    kode, teks = jalankan(saksi, "terima", berkas, "--dir", d)
    assert kode == 0, teks
    assert "[BARU]" in teks and posko["titik"].sidik_jari_akar in teks and "[TERCATAT]" in teks
    tt = tmp_path / "TANDA-TERIMA-saksi.json"
    kode, teks = jalankan(saksi, "periksa-tanda-terima", tt, "--kunci", sj)
    assert kode == 0 and "[SAH]" in teks and "Posko RS Uji" in teks
    # Tanda terima disunting → tanda tangan tidak sah; kunci atasan lain → ditolak.
    u = json.loads(tt.read_text())
    u["entri"]["nomor"] += 5
    tt.write_text(json.dumps(u))
    assert jalankan(saksi, "periksa-tanda-terima", tt, "--kunci", sj)[0] == 1
    assert jalankan(saksi, "periksa-tanda-terima", tt, "--kunci", "ab" * 32)[0] == 1


def test_saksi_berikutnya_maju_dan_status_mencatat_pengirim(posko, tmp_path):
    d, _ = jenjang(tmp_path, "atasan", "Sansidam Uji")
    isi(posko)
    assert jalankan(saksi, "terima", ekspor(posko, "s1.json"), "--dir", d)[0] == 0
    isi(posko, 12)
    kode, teks = jalankan(saksi, "terima", ekspor(posko, "s2.json"), "--dir", d)
    assert kode == 0 and "[MAJU]" in teks and "isi lama sama persis" in teks, teks
    kode, teks = jalankan(saksi, "status", "--dir", d)
    assert kode == 0 and "Posko RS Uji" in teks and teks.count("\n") == 1


def test_saksi_lama_sesudah_saksi_baru_ditolak_digulung_mundur(posko, tmp_path):
    d, _ = jenjang(tmp_path, "atasan", "Sansidam Uji")
    isi(posko)
    lama = ekspor(posko, "lama.json")
    isi(posko, 12)
    assert jalankan(saksi, "terima", ekspor(posko, "baru.json"), "--dir", d)[0] == 0
    kode, teks = jalankan(saksi, "terima", lama, "--dir", d)
    assert kode == 1 and "digulung mundur" in teks, teks
    assert len(saksi.Jenjang(d).buku()) == 1          # tidak dicatat


def _rantai(kunci: list[Ed25519PrivateKey], isi_log: list[int]) -> list[dict]:
    """Rantai titik periksa sah buatan sendiri (penyerang yang pernah mencuri kunci periode tertentu)."""
    pk = [k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() for k in kunci]
    hasil = []
    for i, n in enumerate(isi_log):
        c = {"versi_format": 1, "no": i + 1, "waktu": "2026-11-11T00:00:00+00:00", "alasan": "BERKALA",
             "log": {"audit_log": {"jumlah": n, "sha256_kumulatif": f"{n:064x}"}},
             "kunci_publik": pk[i], "kunci_publik_berikut": pk[i + 1]}
        c["tanda_tangan"] = kunci[i].sign(kanonik_tanda_tangan(c)).hex()
        hasil.append(c)
    return hasil


def _berkas(tmp, nama, rantai):
    import hashlib
    akar = hashlib.sha256(bytes.fromhex(rantai[0]["kunci_publik"])).hexdigest()
    f = tmp / nama
    f.write_text(json.dumps({"jenis": JENIS_SAKSI, "posko": "Posko Bercabang", "sidik_jari_akar": akar,
                             "titik_periksa": rantai}))
    return f, akar


def test_riwayat_bercabang_dengan_tanda_tangan_sah_ditolak(tmp_path):
    """Penyerang yang pernah mencuri kunci periode #2 membuat cabang lain sejak #2: semua tanda tangan sah."""
    kunci = [Ed25519PrivateKey.generate() for _ in range(5)]
    asli = _rantai(kunci, [5, 10, 15])
    cabang = asli[:1] + _rantai(kunci, [5, 9, 20, 25])[1:]
    d, _ = jenjang(tmp_path, "atasan", "Sansidam Uji")
    f1, akar = _berkas(tmp_path, "asli.json", asli)
    assert jalankan(saksi, "terima", f1, "--dir", d)[0] == 0
    f2, _ = _berkas(tmp_path, "cabang.json", cabang)
    assert vtp.periksa_rantai(cabang, akar) is None    # sah secara kriptografi …
    kode, teks = jalankan(saksi, "terima", f2, "--dir", d)
    assert kode == 1 and "bercabang" in teks and "#2" in teks, teks   # … tetapi bercabang dari saksi


def test_berkas_disunting_atau_pengirim_tak_diharapkan_ditolak(posko, tmp_path):
    d, _ = jenjang(tmp_path, "atasan", "Sansidam Uji")
    isi(posko)
    f = ekspor(posko)
    kode, teks = jalankan(saksi, "terima", f, "--dir", d, "--harap", "cd" * 32)
    assert kode == 1 and "tidak sama dengan yang diharapkan" in teks
    j = json.loads(f.read_text())
    j["titik_periksa"][0]["log"]["audit_log"]["jumlah"] += 1
    f.write_text(json.dumps(j))
    kode, teks = jalankan(saksi, "terima", f, "--dir", d)
    assert kode == 1 and "tanda tangan" in teks.lower()
    f.write_text("bukan json")
    assert jalankan(saksi, "terima", f, "--dir", d)[0] == 1
    assert jalankan(saksi, "terima", tmp_path / "tidak-ada.json", "--dir", d)[0] == 2
    assert not (d / "buku_saksi.jsonl").exists()


def test_buku_saksi_sendiri_disunting_tertangkap(posko, tmp_path):
    d, _ = jenjang(tmp_path, "atasan", "Sansidam Uji")
    isi(posko)
    assert jalankan(saksi, "terima", ekspor(posko, "s1.json"), "--dir", d)[0] == 0
    buku = d / "buku_saksi.jsonl"
    e = json.loads(buku.read_text())
    e["nomor"] = 1
    buku.write_text(json.dumps(e) + "\n")
    isi(posko, 6)
    kode, teks = jalankan(saksi, "terima", ekspor(posko, "s2.json"), "--dir", d)
    assert kode == 1 and "Buku Saksi jenjang ini sendiri rusak" in teks


# ---------------------------------------------------------------- satuan atasan → jenjang di atasnya
def test_rekap_berjenjang_dan_jenjang_bawah_menulis_ulang_bukunya_tertangkap(posko, tmp_path):
    bawah, sj_bawah = jenjang(tmp_path, "sansidam", "Sansidam Uji")
    atas, _ = jenjang(tmp_path, "pussiberad", "Pussiberad Uji")
    isi(posko)
    assert jalankan(saksi, "terima", ekspor(posko, "s1.json"), "--dir", bawah)[0] == 0
    isi(posko, 6)
    assert jalankan(saksi, "terima", ekspor(posko, "s2.json"), "--dir", bawah)[0] == 0
    r1 = tmp_path / "rekap1.json"
    assert jalankan(saksi, "rekap", "--dir", bawah, "--keluar", r1)[0] == 0
    kode, teks = jalankan(saksi, "terima", r1, "--dir", atas, "--harap", sj_bawah)
    assert kode == 0 and "[BARU]" in teks and "Sansidam Uji" in teks, teks

    # Sansidam (pemegang kuncinya sendiri) menghapus entri pertama lalu menandatangani ulang seluruh buku.
    benih, pk, _ = saksi.Jenjang(bawah).kunci()
    buku = saksi.Jenjang(bawah).buku()[1:]
    sebelumnya = saksi.NOL
    for i, e in enumerate(buku, start=1):
        e["no"], e["sebelumnya"] = i, sebelumnya
        e["tanda_tangan"] = saksi.tandatangani(benih, saksi.pesan_entri(e)).hex()
        sebelumnya = saksi.hashlib.sha256(saksi.kanonik(e)).hexdigest()
    (bawah / "buku_saksi.jsonl").write_text("".join(json.dumps(e) + "\n" for e in buku))
    assert saksi.Jenjang(bawah).buku()                  # sah secara kriptografi di jenjangnya sendiri …
    r2 = tmp_path / "rekap2.json"
    assert jalankan(saksi, "rekap", "--dir", bawah, "--keluar", r2)[0] == 0
    kode, teks = jalankan(saksi, "terima", r2, "--dir", atas)
    assert kode == 1 and ("digulung mundur" in teks or "bercabang" in teks), teks   # … tetapi tertangkap di atasnya


def test_rekap_milik_sendiri_atau_disunting_ditolak(posko, tmp_path):
    d, _ = jenjang(tmp_path, "sansidam", "Sansidam Uji")
    isi(posko)
    jalankan(saksi, "terima", ekspor(posko), "--dir", d)
    r = tmp_path / "rekap.json"
    jalankan(saksi, "rekap", "--dir", d, "--keluar", r)
    kode, teks = jalankan(saksi, "terima", r, "--dir", d)
    assert kode == 1 and "jenjang ini sendiri" in teks
    atas, _ = jenjang(tmp_path, "atas", "Atas Uji")
    j = json.loads(r.read_text())
    j["buku"][0]["pengirim"]["label"] = "Posko Lain"
    r.write_text(json.dumps(j))
    kode, teks = jalankan(saksi, "terima", r, "--dir", atas)
    assert kode == 1 and "tanda tangan" in teks


# ---------------------------------------------------------------- pemeriksaan di posko dengan saksi dari atasan
def test_auditor_dengan_saksi_cocok(posko, tmp_path, monkeypatch):
    isi(posko)
    f = ekspor(posko)
    isi(posko, 7)
    kode, teks = auditor(posko, f, monkeypatch)
    assert kode == 0 and "[COCOK]" in teks, teks


def test_auditor_dengan_saksi_menangkap_gulung_mundur_log_dan_titik_periksa(posko, tmp_path, monkeypatch):
    d = posko["dir"]
    isi(posko)
    simpan = {n: (d / n).read_text() for n in ("audit_log.jsonl", "titik_periksa.jsonl")}
    isi(posko, 9)
    f = ekspor(posko)
    for n, teks in simpan.items():                      # penyerang mengembalikan keduanya ke keadaan lama
        (d / n).write_text(teks)
    kode, teks = jalankan(vtp, "--akar", posko["titik"].sidik_jari_akar, "--titik", d / "titik_periksa.jsonl",
                          "--log", f"audit_log={d / 'audit_log.jsonl'}",
                          "--log", f"rantai_bukti={d / 'rantai_bukti.jsonl'}")
    assert kode == 0, teks                              # tanpa saksi: tetap tampak sah
    kode, teks = auditor(posko, f, monkeypatch)
    assert kode == 1 and "digulung mundur" in teks and "satuan atasan" in teks, teks


def test_auditor_menolak_saksi_akar_lain_atau_bukan_saksi(posko, tmp_path, monkeypatch):
    isi(posko)
    kunci = [Ed25519PrivateKey.generate() for _ in range(3)]
    f, _ = _berkas(tmp_path, "lain.json", _rantai(kunci, [5, 10]))
    kode, teks = auditor(posko, f, monkeypatch)
    assert kode == 1 and "tidak sah untuk akar ini" in teks
    f.write_text(json.dumps({"jenis": "lain"}))
    assert auditor(posko, f, monkeypatch)[0] == 1
    assert auditor(posko, tmp_path / "tidak-ada.json", monkeypatch)[0] == 2


# ---------------------------------------------------------------- loket server
@pytest.fixture
def klien():
    PEMBATAS.reset()
    return TestClient(main.app)


def masuk(klien, nama="operator", sandi="sandi-operator-uji-123"):
    j = klien.post("/api/login", json={"nama": nama, "sandi": sandi}).json()
    return {"Authorization": f"Bearer {j['token']}"}


def test_loket_saksi_mode_demo_409_dan_pengamat_403(klien):
    assert not main.TITIK.aktif
    r = klien.post("/api/saksi", headers=masuk(klien))
    assert r.status_code == 409 and "demo" in r.json()["detail"].lower()
    r = klien.post("/api/saksi", headers=masuk(klien, "pengamat", "sandi-pengamat-uji-123"))
    assert r.status_code == 403
    assert klien.post("/api/saksi").status_code == 401


def test_loket_saksi_mengunduh_berkas_yang_diterima_atasan(klien, posko, tmp_path, monkeypatch):
    monkeypatch.setattr(main, "TITIK", posko["titik"])
    monkeypatch.setenv("NS_NAMA_POSKO", "Posko RSAD Uji")
    isi(posko)
    r = klien.post("/api/saksi", headers=masuk(klien))
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/json")
    assert re.search(r'filename="SAKSI-NusantaraShield-titik\d+-\d{8}-\d{4}\.json"', r.headers["content-disposition"])
    f = tmp_path / "unduhan.json"
    f.write_bytes(r.content)
    assert json.loads(r.content)["posko"] == "Posko RSAD Uji"
    d, _ = jenjang(tmp_path, "atasan", "Sansidam Uji")
    kode, teks = jalankan(saksi, "terima", f, "--dir", d, "--harap", posko["titik"].sidik_jari_akar)
    assert kode == 0, teks
    assert any(e["aksi"] == "EKSPOR_SAKSI" for e in main.LOG.daftar(20))
