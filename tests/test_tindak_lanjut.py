# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
Uji v5.4.3: bagian "Tindak lanjut yang disarankan" di LAPSIT.

Prinsip yang dikunci:
- Setiap butir lahir dari data yang sama dengan isi laporan, dengan aturan tetap (bukan AI), dan menyebut dasarnya.
- Saran mengikuti doktrin: selama bukti belum aman, saran SEGERA adalah mengamankan bukti, bukan memutus.
- Saran tidak menjalankan apa pun: mengekspor LAPSIT tidak mengubah layanan, insiden, atau antrean SOAR.
- Urutan selalu SEGERA → HARI INI → RUTIN; rantai audit yang tidak utuh selalu di urutan pertama.
"""

import pytest
from fastapi.testclient import TestClient

from app import lapsit, main
from app.audit import LOG
from app.istilah import ISTILAH
from app.keamanan import PEMBATAS
from test_insiden_temuan import impor
from test_ot_mitre_lapsit import teks_pdf

JAM = {"t": 9000.0}


@pytest.fixture(autouse=True)
def bersihkan():
    PEMBATAS.reset()
    main.LAYANAN = main.salin_layanan_awal()
    JAM["t"] = 9000.0
    main.MENARA._jam = lambda: JAM["t"]
    main.MENARA.reset()
    main.MENARA.osint.berikut = 1e12


@pytest.fixture
def k():
    return TestClient(main.app)


def masuk(k, nama="operator", sandi="sandi-operator-uji-123"):
    j = k.post("/api/login", json={"nama": nama, "sandi": sandi}).json()
    return {"Authorization": f"Bearer {j['token']}"}


def saran(titik=None):
    with main._kunci_state:
        data = [main._tampilan(l) for l in main.LAYANAN.values()]
        rincian = main.MENARA.rincian_lapsit(main.LAYANAN)
        peringatan = main.MENARA.peringatan_lapsit(main.LAYANAN)
    return lapsit.tindak_lanjut(data, rincian, peringatan, LOG.verifikasi(), titik)


def maju(k, h, kali=10):
    for _ in range(kali):
        JAM["t"] += 1.5
        k.get("/api/telemetri", headers=h)


def test_kondisi_rutin_menyarankan_cadangan_tanpa_butir_segera(k):
    b = saran()
    assert not [x for x in b if x["prioritas"] == "SEGERA"]
    pemasok = next(x for x in b if "Pemasok" in x["tindakan"])
    assert pemasok["prioritas"] == "HARI INI" and "52 jam (batas 24 jam)" in pemasok["dasar"]
    assert any(x["prioritas"] == "RUTIN" and "SIMRS" in x["tindakan"] and "belum pernah diuji" in x["dasar"]
               for x in b)
    teks = teks_pdf(k.post("/api/lapsit", headers=masuk(k)).content)
    for kata in ("Tindak Lanjut yang Disarankan", "Dasar (data yang memicu)", "bukan oleh AI", "Saran, bukan perintah",
                 "HARI INI", ISTILAH["ttd_judul"]):
        assert kata in teks, kata


def test_saran_mengikuti_doktrin_bukti_dulu_lalu_putus_lalu_serahkan(k):
    h = masuk(k)
    assert k.post("/api/simulasi", headers=h, json={"layanan_id": "kesehatan", "skenario": "ransomware"}).status_code == 200
    segera = [x for x in saran() if x["prioritas"] == "SEGERA"]
    assert len(segera) == 1 and segera[0]["tindakan"].startswith(ISTILAH["langkah_bukti"])
    assert "belum ada tindakan penahanan" in segera[0]["dasar"]

    assert k.post("/api/soar/jalankan", headers=h,
                  json={"layanan_id": "kesehatan", "aksi": "amankan_bukti"}).status_code == 200
    segera = [x for x in saran() if x["prioritas"] == "SEGERA"]
    assert len(segera) == 1 and "Selesaikan tindakan pemutus" in segera[0]["tindakan"]
    assert "BB-" in segera[0]["dasar"]

    assert k.post("/api/soar/jalankan", headers=h, json={"layanan_id": "kesehatan", "aksi": "isolasi"}).status_code == 200
    maju(k, h)
    b = saran()
    assert not [x for x in b if x["prioritas"] == "SEGERA"]
    teks = {x["tindakan"] for x in b if x["prioritas"] == "HARI INI"}
    assert any("Jalankan prosedur darurat RS Kesdam" in t for t in teks)
    assert any("Uji pulih cadangan RS Kesdam" in t and "sebelum pemulihan" in t for t in teks)   # cadangan belum diuji
    serah = next(x for x in b if "Serahkan berita acara bukti BB-" in x["tindakan"])
    assert "mengetahui" in serah["pelaksana"] and ISTILAH["buku_bukti"] in serah["dasar"]


def test_ekspor_lapsit_tidak_menjalankan_saran_apa_pun(k):
    h = masuk(k)
    assert k.post("/api/simulasi", headers=h, json={"layanan_id": "kesehatan", "skenario": "ransomware"}).status_code == 200
    sebelum = main.LAYANAN["kesehatan"]["insiden"]["langkah_selesai"][:]
    awal = LOG.verifikasi()["jumlah"]
    assert k.post("/api/lapsit", headers=h).status_code == 200
    assert main.LAYANAN["kesehatan"]["insiden"]["langkah_selesai"] == sebelum and not any(sebelum)
    assert main.MENARA.rincian_lapsit(main.LAYANAN)["insiden"]["kesehatan"].get("bukti") is None
    aksi = [e["aksi"] for e in LOG.daftar(LOG.verifikasi()["jumlah"] - awal)]
    assert aksi == ["EKSPOR_LAPSIT"]                                        # satu-satunya jejak: ekspor itu sendiri


def test_temuan_log_asli_terbuka_disarankan_untuk_triase_lalu_hilang_setelah_ditutup(k):
    h = masuk(k)
    tm = impor(k, h, "auth.log")["login_tembus"]
    triase = [x for x in saran() if tm["id"] in x["tindakan"]]
    assert len(triase) == 1 and triase[0]["prioritas"] == "HARI INI"
    assert "usulan server" in triase[0]["tindakan"] and "alasan tertulis" in triase[0]["tindakan"]
    r = k.post("/api/peringatan/tutup", headers=h, json={"aset_id": "ssh", "status": "false_positive",
                                                          "alasan": "Uji penetrasi resmi oleh tim jaringan satuan"})
    assert r.status_code == 200, r.text
    assert not [x for x in saran() if tm["id"] in x["tindakan"]]


def test_isolasi_darurat_tanpa_bukti_meminta_bukti_susulan():
    layanan = [{"id": "x", "nama": "Layanan X", "insiden": {"judul": "Ransomware", "mulai": "2026-11-13T00:00:00+00:00"},
                "jam_sejak_backup": 1, "backup_teruji": True}]
    rincian = {"insiden": {"x": {"darurat": {"petugas": "operator", "waktu": "2026-11-13T00:01:00+00:00",
                                             "alasan": "Agen forensik tidak merespons"},
                                 "ir": {"nomor": "IR-2026-001"}, "mttc": 3}}, "ioc": []}
    b = lapsit.tindak_lanjut(layanan, rincian, [], {"utuh": True})
    assert b[0]["prioritas"] == "SEGERA" and "bukti susulan" in b[0]["tindakan"]
    assert "Isolasi darurat oleh akun operator" in b[0]["dasar"]
    assert not [x for x in b if "Serahkan berita acara" in x["tindakan"]]         # belum ada bukti untuk diserahkan


def test_audit_tidak_utuh_selalu_paling_atas_dan_urutan_prioritas_tetap():
    layanan = [{"id": "a", "nama": "A", "insiden": None, "jam_sejak_backup": 99, "backup_teruji": False},
               {"id": "b", "nama": "B", "insiden": None, "jam_sejak_backup": 1, "backup_teruji": False}]
    latihan = [{"id": "DET-0001", "jenis": "deteksi", "kelas": "terbuka", "usul_insiden": None,
                "judul": "Pemindaian port · Gerbang", "status": "Aset dinaikkan ke WASPADA"},
               {"id": "DET-0002", "jenis": "deteksi", "kelas": "pantau", "judul": "x", "status": "Dipantau"}]
    b = lapsit.tindak_lanjut(layanan, {"insiden": {}, "ioc": []}, latihan,
                             {"utuh": False, "pesan": "Rantai putus di entri #4"},
                             {"aktif": True, "no": 3, "saksi_no": None})
    assert b[0]["prioritas"] == "SEGERA" and "verifikasi_audit.py" in b[0]["tindakan"] and "#4" in b[0]["dasar"]
    urut = [lapsit.URUTAN_PRIORITAS.index(x["prioritas"]) for x in b]
    assert urut == sorted(urut)
    assert any(x["prioritas"] == "RUTIN" and "Berkas Saksi" in x["tindakan"] for x in b)
    # temuan latihan (bukan impor) tidak bisa dibuka dari temuan: saran tidak menjanjikan jalur yang tidak ada
    det = [x for x in b if "DET-" in x["tindakan"]]
    assert len(det) == 1 and "tangani melalui playbook" in det[0]["tindakan"] and "usulan server" not in det[0]["tindakan"]
    assert not [x for x in lapsit.tindak_lanjut([], {"insiden": {}, "ioc": []}, [], {"utuh": True},
                                                {"aktif": True, "no": 3, "saksi_no": 2})]   # saksi sudah ada


def test_tanpa_tindak_lanjut_laporan_menyatakannya():
    b = lapsit.tindak_lanjut([{"id": "a", "nama": "A", "insiden": None, "jam_sejak_backup": 1, "backup_teruji": True}],
                             {"insiden": {}, "ioc": []}, [], {"utuh": True})
    assert b == []
    isi = lapsit._bagian_tindak_lanjut(b, lapsit._gaya(), 6)
    assert any("Tidak ada tindak lanjut" in getattr(x, "text", "") for x in isi)
    # istilah asing dicetak miring (PUEBI), tetapi nama berkas dan jalur tidak disentuh
    assert lapsit._miring("Catatan tebusan ditemukan di server.") == "Catatan tebusan ditemukan di <i>server</i>."
    assert lapsit._miring("berkas server.log di tools/server.py") == "berkas server.log di tools/server.py"
    # sel waktu di tabel tidak terlipat: waktu terpanjang (zona WITA) + bantalan sel muat di kolom tersempit (39 mm)
    from datetime import datetime
    from reportlab.lib.units import mm
    from reportlab.pdfbase.pdfmetrics import stringWidth
    terpanjang = lapsit.tulis_waktu(datetime(2026, 12, 28, 23, 59, 59), "WITA", tabel=True)
    assert stringWidth(terpanjang, "Helvetica", 8) + 12 <= 39 * mm
    assert lapsit.tulis_waktu(datetime(2026, 11, 13, 8, 2, 1), "WIB") == "13 November 2026 pukul 08.02.01 WIB"
    assert lapsit._teknik("T1486 Data Encrypted for Impact; T0886 Remote Services (ICS)") == \
        "T1486 <i>Data Encrypted for Impact</i>; T0886 <i>Remote Services</i> (ICS)"
