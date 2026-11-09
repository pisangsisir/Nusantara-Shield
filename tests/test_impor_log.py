# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
Uji Fase 3: impor log ASLI secara luring (auth.log OpenSSH, log firewall UFW/iptables, CSV).

Prinsip yang dikunci:
- Aturan yang menilai log impor sama persis dengan aturan latihan; tidak ada jalan pintas.
- Validasi ketat di batas kepercayaan: IP, port, dan jenis yang tidak sah dilewati dan dihitung, bukan ditebak.
  Berkas yang tidak dikenali sama sekali ditolak 422.
- Privasi: nama akun dalam log tidak ikut ke peristiwa; isi log tidak masuk log audit.
- Dua kunci tetap: temuan dari log asli hanya menaikkan WASPADA; tanpa insiden, bukti, isolasi, atau antrean SOAR.
- Hanya jalur impor yang boleh menerima ≈2 MB, dan hanya bila membawa token; jalur lain tetap 16 KB.
"""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import main
from app.audit import LOG
from app.impor_log import MAKS_BARIS, GalatImpor, baca
from app.keamanan import PEMBATAS
from app.telemetri import SIMPUL

CONTOH = Path(__file__).resolve().parent.parent / "docs" / "contoh-log"
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


def impor(k, h, berkas, **lain):
    return k.post("/api/deteksi/impor", headers=h,
                  json={"nama": berkas, "isi": (CONTOH / berkas).read_text(encoding="utf-8"), **lain})


def potret(k, h):
    return k.get("/api/telemetri", headers=h).json()


# ---------------------------------------------------------------- pembaca (unit, tanpa server)
def test_auth_log_openssh_dibaca_tanpa_nama_akun():
    ev, r = baca((CONTOH / "auth.log").read_text(), SIMPUL)
    assert r == {"format": "auth.log (OpenSSH)", "baris": 13, "dikenali": 12, "diabaikan": 1, "rentang_detik": 273}
    assert [e["berhasil"] for _, e in ev].count(False) == 10
    assert all(e["aset"] == "ssh" and e["jenis"] == "login" for _, e in ev)
    teks = json.dumps([e for _, e in ev])
    assert not any(nama in teks for nama in ("admin", "operator", "user0"))      # nama akun tidak disalin


def test_log_firewall_ufw_menjadi_koneksi_dan_aset_dikenali_dari_port():
    ev, r = baca((CONTOH / "ufw.log").read_text(), SIMPUL)
    assert r["format"] == "firewall (UFW/iptables)" and r["dikenali"] == 20
    assert {e["port"] for _, e in ev if e["aset"] == "portal"} == {443}


def test_csv_berkepala_dan_alamat_ip_aset_dipetakan():
    ev, r = baca((CONTOH / "peristiwa-ot.csv").read_text(), SIMPUL)
    assert r["format"] == "csv" and r["dikenali"] == 5
    assert [e["jenis"] for _, e in ev] == ["koneksi_ot", "modbus", "koneksi_ot", "modbus", "modbus"]
    assert {e["aset"] for _, e in ev} == {"genset"}                 # 192.0.2.120 → pengendali genset


def test_baris_tidak_sah_dilewati_dan_dihitung():
    isi = "\n".join(["waktu,jenis,sumber,aset,berhasil,ip,port",
                     "2026-10-27T10:00:00Z,login,999.1.1.1,ssh,tidak,,",        # IP tidak sah
                     "2026-10-27T10:00:01Z,koneksi,203.0.113.5,,,192.0.2.10,70000",  # port di luar rentang
                     "2026-10-27T10:00:02Z,serang,203.0.113.5,ssh,,,",           # jenis tidak dikenal
                     "kemarin,login,203.0.113.5,ssh,tidak,,",                    # waktu tidak sah
                     "2026-10-27T10:00:03Z,login,203.0.113.5,tidak-ada,tidak,,", # aset tidak dikenal
                     "2026-10-27T10:00:04Z,login,203.0.113.5,ssh,tidak,,"])      # satu-satunya yang sah
    ev, r = baca(isi, SIMPUL)
    assert (r["baris"], r["dikenali"], r["diabaikan"]) == (6, 1, 5) and ev[0][1]["sumber"] == "203.0.113.5"


def test_stempel_waktu_iso_rsyslog_dikenali():
    isi = "2026-10-27T14:02:11.123+07:00 posko sshd[1]: Failed password for root from 203.0.113.9 port 2 ssh2"
    ev, _ = baca(isi, SIMPUL)
    assert ev[0][1] == {"jenis": "login", "sumber": "203.0.113.9", "aset": "ssh", "berhasil": False}


@pytest.mark.parametrize("isi", ["", "halo dunia\nini bukan log", "waktu,jenis,sumber\n"])
def test_berkas_tak_dikenali_ditolak(isi):
    with pytest.raises(GalatImpor):
        baca(isi, SIMPUL)


def test_berkas_terlalu_panjang_ditolak():
    with pytest.raises(GalatImpor):
        baca("x\n" * (MAKS_BARIS + 1), SIMPUL)


def test_modul_impor_tidak_menyentuh_jaringan():
    sumber = Path(main.__file__).with_name("impor_log.py").read_text(encoding="utf-8")
    for terlarang in ("import socket", "import urllib", "import requests", "import httpx", "subprocess"):
        assert terlarang not in sumber


# ---------------------------------------------------------------- terpadu: aturan sama, dua kunci utuh
def test_impor_auth_log_menaikkan_waspada_tanpa_memutus(k):
    h = masuk(k)
    r = impor(k, h, "auth.log")
    assert r.status_code == 200, r.text
    j = r.json()
    assert {t["aturan"] for t in j["temuan"]} == {"login_gagal", "login_tembus"} and j["waspada"] == ["Akses admin SSH"]
    assert {m["id"] for t in j["temuan"] for m in t["mitre"]} == {"T1110", "T1078"}
    p = potret(k, h)
    ssh = {x["id"]: x for x in p["cti"]["prediksi"]}["ssh"]
    assert ssh["proaktif"]
    det = [x for x in p["peringatan"] if x["jenis"] == "deteksi"]
    assert det and all(x["sumber_data"] == "Sumber: log impor «auth.log» dari Operator · aturan deteksi berjalan nyata"
                       for x in det)
    assert not any(l["insiden"] for l in main.LAYANAN.values())
    assert main.MENARA._antre_soar == [] and main.MENARA._bukti == {}


def test_impor_csv_ot_dan_firewall_memakai_aturan_yang_sama(k):
    h = masuk(k)
    ot = impor(k, h, "peristiwa-ot.csv").json()
    assert {t["aturan"] for t in ot["temuan"]} == {"ot_tanpa_izin", "tulis_ot_luar_jadwal", "rantai_it_ot"}
    assert ot["waspada"] == ["Pengendali genset"]
    fw = impor(k, h, "ufw.log").json()
    assert [t["aturan"] for t in fw["temuan"]] == ["pindai_port"] and fw["temuan"][0]["aset"] == ["portal"]


def test_log_audit_hanya_mencatat_nama_berkas_dan_jumlah(k):
    h = masuk(k)
    impor(k, h, "auth.log")
    entri = [e for e in LOG.daftar(500) if e["aksi"] == "IMPOR_LOG"][0]
    assert entri["detail"] == {"berkas": "auth.log", "baris": 13, "dikenali": 12, "temuan": 2}
    assert "203.0.113.91" not in str(LOG.daftar(500))                  # isi log tidak masuk log audit


def test_nama_berkas_dibersihkan_dan_berkas_aneh_ditolak(k):
    h = masuk(k)
    r = k.post("/api/deteksi/impor", headers=h, json={"nama": "../../etc/pass<wd>", "isi": (CONTOH / "auth.log").read_text()})
    assert r.status_code == 200 and r.json()["berkas"] == "pass_wd_"
    assert k.post("/api/deteksi/impor", headers=h, json={"nama": "x.log", "isi": "bukan log"}).status_code == 422
    assert k.post("/api/deteksi/impor", headers=h,
                  json={"nama": "x.log", "isi": "a", "aset_id": "tidak-ada"}).status_code == 422
    assert k.post("/api/deteksi/impor", headers=h, json={"nama": "x.log", "isi": "a", "lain": 1}).status_code == 422


# ---------------------------------------------------------------- akses dan batas ukuran
def test_hanya_operator_dan_wajib_token(k):
    assert k.post("/api/deteksi/impor", json={"nama": "a.log", "isi": "a"}).status_code == 401
    hp = masuk(k, "pengamat", "sandi-pengamat-uji-123")
    assert impor(k, hp, "auth.log").status_code == 403


def test_tanpa_token_body_besar_ditolak_sebelum_dibaca(k):
    r = k.post("/api/deteksi/impor", content=b"x" * 100_000, headers={"Content-Type": "application/json"})
    assert r.status_code == 401 and r.headers["connection"] == "close"


def test_hanya_jalur_impor_yang_boleh_lebih_dari_16_kb(k):
    h = masuk(k)
    besar = "\n".join([(CONTOH / "auth.log").read_text()] * 40)          # ≈45 KB: lolos di jalur impor
    assert len(besar.encode()) > 16 * 1024
    assert k.post("/api/deteksi/impor", headers=h, json={"nama": "besar.log", "isi": besar}).status_code == 200
    r = k.post("/api/simulasi", headers=h, json={"layanan_id": "imigrasi", "skenario": "ddos", "x": "y" * 20_000})
    assert r.status_code == 413                                         # jalur lain tetap 16 KB
    r = k.post("/api/deteksi/impor", headers=h, content=b"x" * 2_700_000)
    assert r.status_code == 413                                         # di atas ≈2,6 MB: ditolak sebelum router


def test_impor_dibatasi_laju(k):
    h = masuk(k)
    kode = [k.post("/api/deteksi/impor", headers=h, json={"nama": "x.log", "isi": "bukan log"}).status_code
            for _ in range(7)]
    assert kode[:6] == [422] * 6 and kode[6] == 429
