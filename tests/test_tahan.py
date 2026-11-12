# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
Uji v5.4.2: tahan-untuk-konfirmasi dijaga SERVER, bukan hanya peramban.

Setiap jalur pemutus (Eksekusi Isolasi, tindakan pemutus satuan, Isolasi Darurat) wajib membawa token tahan yang
diminta saat tombol MULAI ditahan. Ditolak 428 bila token tidak ada, dipakai ulang, milik akun/layanan/tombol lain,
kedaluwarsa, atau eksekusi datang lebih cepat dari batas minimum (0,5 / 1,4 detik; tombol 0,6 / 1,5 detik).
Lama tahan tercatat di log audit. Uji di berkas ini memakai batas ASLI (penanda tahan_asli).
"""

import time

import pytest
from fastapi.testclient import TestClient

from app import main
from app.audit import LOG
from app.keamanan import PEMBATAS

pytestmark = pytest.mark.tahan_asli


@pytest.fixture(autouse=True)
def bersihkan():
    PEMBATAS.reset()
    main.LAYANAN = main.salin_layanan_awal()
    main.MENARA.reset()
    main._TAHAN.clear()


@pytest.fixture
def k():
    return TestClient(main.app)


def masuk(k, nama="operator", sandi="sandi-operator-uji-123"):
    j = k.post("/api/login", json={"nama": nama, "sandi": sandi}).json()
    return {"Authorization": f"Bearer {j['token']}"}


def insiden(k, h, lid="pajak", skenario="ransomware", **lain):
    r = k.post("/api/simulasi", headers=h, json={"layanan_id": lid, "skenario": skenario, **lain})
    assert r.status_code == 200, r.text


def token(k, h, lid="pajak", tujuan="isolasi"):
    r = k.post("/api/tahan", headers=h, json={"layanan_id": lid, "tujuan": tujuan})
    assert r.status_code == 200, r.text
    return r.json()


def isolasi(k, h, tahan, lid="pajak", aksi="isolasi"):
    return k.post("/api/soar/jalankan", headers=h, json={"layanan_id": lid, "aksi": aksi, "tahan": tahan})


def test_tanpa_token_ditolak_428(k):
    h = masuk(k)
    insiden(k, h)
    r = isolasi(k, h, None)
    assert r.status_code == 428 and "ditahan 0,6 detik" in r.json()["detail"]
    assert main.LAYANAN["pajak"]["insiden"]["langkah_selesai"][1] is False


def test_dilepas_terlalu_cepat_ditolak_lalu_ditahan_penuh_diterima_dan_tercatat(k):
    h = masuk(k)
    insiden(k, h)
    t = token(k, h)
    assert t["minimal_ms"] == 600
    r = isolasi(k, h, t["token"])
    assert r.status_code == 428 and "dilepas setelah 0," in r.json()["detail"]
    t = token(k, h)
    time.sleep(0.52)
    r = isolasi(k, h, t["token"])
    assert r.status_code == 200, r.text
    e = next(e for e in LOG.daftar(10) if e["aksi"] == "SOAR_JALANKAN")
    assert e["detail"]["tahan_ms"] >= 500


def test_token_sekali_pakai_dan_terikat_akun_layanan_tujuan(k, monkeypatch):
    monkeypatch.setattr(main, "MIN_TAHAN", {"isolasi": 0.0, "darurat": 0.0})
    h = masuk(k)
    insiden(k, h)
    insiden(k, h, "kesehatan", "ddos")
    t = token(k, h)["token"]
    assert isolasi(k, h, t, lid="kesehatan").status_code == 428          # layanan lain
    assert isolasi(k, h, t).status_code == 428                            # sudah dipakai (habis saat ditolak)
    t = token(k, h, tujuan="darurat")["token"]
    assert isolasi(k, h, t).status_code == 428                            # tombol lain
    t = token(k, h)["token"]
    assert isolasi(k, h, t).status_code == 200
    assert isolasi(k, h, t).status_code == 428                            # dipakai ulang


def test_token_kedaluwarsa_ditolak(k, monkeypatch):
    h = masuk(k)
    insiden(k, h)
    t = token(k, h)["token"]
    akun, lid, tujuan, mulai = main._TAHAN[t]
    main._TAHAN[t] = (akun, lid, tujuan, mulai - main.UMUR_TAHAN - 1)
    r = isolasi(k, h, t)
    assert r.status_code == 428 and "kedaluwarsa" in r.json()["detail"]


def test_tindakan_pemutus_satuan_juga_wajib_ditahan(k, monkeypatch):
    h = masuk(k)
    insiden(k, h)
    assert "isolasi_otomatis" in main.AKSI_PEMUTUS and "amankan_bukti" not in main.AKSI_PEMUTUS
    assert isolasi(k, h, None, aksi="amankan_bukti").status_code == 200     # bukti tidak memutus: tanpa tahan
    assert isolasi(k, h, None, aksi="isolasi_otomatis").status_code == 428
    monkeypatch.setattr(main, "MIN_TAHAN", {"isolasi": 0.0, "darurat": 0.0})
    assert isolasi(k, h, token(k, h)["token"], aksi="isolasi_otomatis").status_code == 200


def test_isolasi_darurat_butuh_tahan_14_detik(k):
    h = masuk(k)
    insiden(k, h, gangguan_bukti=True)
    alasan = "Agen forensik tidak merespons, enkripsi menyebar"
    darurat = lambda tahan: k.post("/api/soar/darurat", headers=h, json={"layanan_id": "pajak", "alasan": alasan,
                                                                          "tahan": tahan})
    assert darurat(None).status_code == 428
    t = token(k, h, tujuan="darurat")
    assert t["minimal_ms"] == 1500
    time.sleep(0.6)
    r = darurat(t["token"])
    assert r.status_code == 428 and "1,5 detik" in r.json()["detail"]
    t = token(k, h, tujuan="darurat")
    time.sleep(1.42)
    r = darurat(t["token"])
    assert r.status_code == 200, r.text
    assert r.json()["tahan_ms"] >= 1400


def test_hanya_operator_yang_bisa_meminta_token(k):
    assert k.post("/api/tahan", json={"layanan_id": "pajak", "tujuan": "isolasi"}).status_code == 401
    hp = masuk(k, "pengamat", "sandi-pengamat-uji-123")
    assert k.post("/api/tahan", headers=hp, json={"layanan_id": "pajak", "tujuan": "isolasi"}).status_code == 403
    h = masuk(k)
    assert k.post("/api/tahan", headers=h, json={"layanan_id": "pajak", "tujuan": "hapus"}).status_code == 422


def test_satu_token_aktif_per_tombol_dan_jumlah_dibatasi(k):
    h = masuk(k)
    a, b = token(k, h)["token"], token(k, h)["token"]
    assert a not in main._TAHAN and b in main._TAHAN                       # tekan ulang membuang token lama
    for lid in ("imigrasi", "perizinan", "kesehatan", "listrik", "logistik"):
        token(k, h, lid)
    assert len(main._TAHAN) <= 200
