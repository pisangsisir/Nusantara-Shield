# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
Uji Fase 3: impor log ASLI secara luring (auth.log OpenSSH, log firewall UFW/iptables, CSV, dan keluaran sensor yang
sudah dimiliki satuan: Wazuh alerts.json serta Suricata eve.json).

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


def test_wazuh_alerts_json_menjadi_upaya_login_tanpa_nama_akun():
    ev, r = baca((CONTOH / "wazuh-alerts.json").read_text(), SIMPUL)
    assert r["format"] == "Wazuh alerts.json" and (r["baris"], r["dikenali"], r["diabaikan"]) == (14, 11, 3)
    assert [e["berhasil"] for _, e in ev] == [False] * 10 + [True]
    assert all(e == {"jenis": "login", "sumber": "203.0.113.77", "aset": "ssh", "berhasil": e["berhasil"]} for _, e in ev)
    # agregat "brute force" Wazuh (5763), sudo, dan FIM tidak dihitung sebagai upaya login; nama akun tidak disalin
    assert not any(n in json.dumps([e for _, e in ev]) for n in ("admin", "svc_backup", "root"))


def test_suricata_eve_json_menjadi_koneksi_koneksi_ot_dan_modbus():
    ev, r = baca((CONTOH / "suricata-eve.json").read_text(), SIMPUL)
    assert r["format"] == "Suricata eve.json" and (r["baris"], r["dikenali"], r["diabaikan"]) == (26, 25, 1)
    jenis = [e["jenis"] for _, e in ev]
    assert jenis.count("koneksi") == 19 and jenis.count("koneksi_ot") == 2 and jenis.count("modbus") == 4
    assert {e["aset"] for _, e in ev if e["jenis"] != "koneksi"} == {"genset"}
    tulis = [e for _, e in ev if e["jenis"] == "modbus" and e["sumber"] == "192.0.2.183"]
    assert [(e["fungsi"], e["jam"]) for e in tulis] == [(3, 14), (6, 14), (16, 14)]


def test_jam_modbus_dari_zona_waktu_sensor_bukan_server(monkeypatch):
    """Jendela pemeliharaan dinilai menurut jam di lokasi sensor (offset di stempel waktu), bukan zona waktu server."""
    import time
    monkeypatch.setenv("TZ", "UTC")
    time.tzset()                                     # server ber-UTC: 23.30 WIB = 16.30 di jam server
    baris = ('{"timestamp":"2026-11-06T23:30:00.000+0700","event_type":"modbus","src_ip":"192.0.2.183",'
             '"dest_ip":"192.0.2.120","dest_port":502,"modbus":{"request":{"function_raw":6}}}')
    try:
        ev, _ = baca(baris, SIMPUL)
    finally:
        monkeypatch.undo()
        time.tzset()
    assert ev[0][1]["jam"] == 23


def test_json_rusak_dan_peristiwa_asing_dilewati_dan_dihitung():
    isi = "\n".join([
        '{"timestamp":"2026-11-06T10:00:00+0700","event_type":"flow","src_ip":"999.1.1.1","dest_ip":"192.0.2.10","dest_port":443}',
        '{"timestamp":"2026-11-06T10:00:01+0700","event_type":"flow","src_ip":"198.51.100.9","dest_ip":"192.0.2.10","dest_port":70000}',
        '{"timestamp":"kemarin","event_type":"flow","src_ip":"198.51.100.9","dest_ip":"192.0.2.10","dest_port":443}',
        '{"timestamp":"2026-11-06T10:00:02+0700","event_type":"modbus","src_ip":"198.51.100.9","dest_ip":"192.0.2.120",'
        '"dest_port":502,"modbus":{"request":{"function_raw":"tulis"}}}',
        '{"timestamp":"2026-11-06T10:00:03+0700","rule":{"groups":["sshd","authentication_failed"]},"agent":{},"data":{}}',
        '{potong',
        '[1, 2]',
        '{"timestamp":"2026-11-06T10:00:04+0700","event_type":"flow","src_ip":"198.51.100.9","dest_ip":"192.0.2.10",'
        '"dest_port":443}'])
    ev, r = baca(isi, SIMPUL)
    assert (r["baris"], r["dikenali"], r["diabaikan"]) == (8, 1, 7) and ev[0][1]["aset"] == "portal"


def test_ekspor_berbentuk_larik_json_juga_diterima():
    import json as j
    larik = [j.loads(b) for b in (CONTOH / "wazuh-alerts.json").read_text().splitlines()]
    ev, r = baca(j.dumps(larik, indent=2), SIMPUL)
    assert r["format"] == "Wazuh alerts.json" and r["dikenali"] == 11 and r["baris"] == 14


@pytest.mark.parametrize("isi", ["", "halo dunia\nini bukan log", "waktu,jenis,sumber\n", '{"event_type":"stats"}'])
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


def test_impor_wazuh_dan_suricata_dinilai_aturan_yang_sama_tanpa_memutus(k):
    h = masuk(k)
    w = impor(k, h, "wazuh-alerts.json").json()
    assert {t["aturan"] for t in w["temuan"]} == {"login_gagal", "login_tembus"} and w["format"] == "Wazuh alerts.json"
    s = impor(k, h, "suricata-eve.json").json()
    assert {t["aturan"] for t in s["temuan"]} == {"pindai_port", "ot_tanpa_izin", "tulis_ot_luar_jadwal", "rantai_it_ot"}
    assert all(t["sumber"] != "192.0.2.140" for t in s["temuan"])          # HMI resmi membaca register: bukan temuan
    assert set(s["waspada"]) >= {"Pengendali genset"}
    # dua kunci tetap utuh: keluaran sensor hanya menaikkan WASPADA, tidak memulai insiden atau memutus apa pun
    assert not any(l["insiden"] for l in main.LAYANAN.values())
    assert main.MENARA._antre_soar == [] and main.MENARA._bukti == {}


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


@pytest.mark.parametrize("otorisasi", ["Bearer palsu", "Bearer ", "Basic abc"])
def test_token_palsu_body_besar_ditolak_sebelum_dibaca(k, otorisasi):
    """Audit v5.4.1: berawalan 'Bearer' saja tidak cukup; token harus sah sebelum ≈2 MB boleh dibaca."""
    r = k.post("/api/deteksi/impor", content=b"x" * 2_400_000,
               headers={"Content-Type": "application/json", "Authorization": otorisasi})
    assert r.status_code == 401 and r.headers["connection"] == "close"


def _baris_fw(sumber="203.0.113.9", tujuan="192.0.2.21", port=22, detik=0):
    return f"Nov  9 10:00:{detik:02d} posko kernel: [UFW BLOCK] IN=eth0 SRC={sumber} DST={tujuan} PROTO=TCP DPT={port}"


@pytest.mark.parametrize("racun", ["SRC=1 DST=1 " * 1500, "SRC=1 " * 20000, "DST=1.1.1.1 SRC=2.2.2.2 " * 900],
                         ids=["src-dst", "src-saja", "urutan-terbalik"])
def test_baris_beracun_diurai_cepat_dan_dilewati(racun):
    """Audit v5.4.1: satu baris 18 KB dulu membuat pola firewall menelusur ulang ±108 detik sambil memegang kunci."""
    import time
    isi = _baris_fw() + "\nNov  9 10:00:01 posko kernel: " + racun + "\n"
    mulai = time.perf_counter()
    _, r = baca(isi, SIMPUL)
    assert time.perf_counter() - mulai < 1.0
    assert r["dikenali"] == 1 and r["diabaikan"] == 1


def test_kolom_firewall_dibaca_tanpa_bergantung_urutan_dan_nilai_tak_sah_dilewati():
    isi = "\n".join([
        "Nov  9 10:00:00 posko kernel: DPT=22 PROTO=TCP DST=192.0.2.21 SRC=203.0.113.9",      # urutan lain: dikenali
        "Nov  9 10:00:01 posko kernel: SRC=203.0.113.9 DST=192.0.2.21 DPT=" + "9" * 5000,    # port ribuan digit
        "Nov  9 10:00:02 posko kernel: SRC=203.0.113.9 DST=192.0.2.21 DPT=70000",            # port di luar jangkauan
        "Nov  9 10:00:03 posko kernel: XSRC=203.0.113.9 DST=192.0.2.21 DPT=22",              # bukan kolom SRC
    ])
    peristiwa, r = baca(isi, SIMPUL)
    assert r["dikenali"] == 1 and r["diabaikan"] == 3
    assert peristiwa[0][1] == {"jenis": "koneksi", "sumber": "203.0.113.9", "ip": "192.0.2.21", "port": 22, "aset": "ssh"}


def test_baris_terlalu_panjang_dilewati_dan_dihitung():
    from app.impor_log import MAKS_PANJANG_BARIS
    panjang = _baris_fw(detik=1) + " PAD=" + "a" * MAKS_PANJANG_BARIS
    _, r = baca(_baris_fw() + "\n" + panjang + "\n", SIMPUL)
    assert r["dikenali"] == 1 and r["diabaikan"] == 1


@pytest.mark.parametrize("isi", [
    "[" * 100_000,                                                                    # larik bersarang sangat dalam
    "waktu,jenis,sumber\n\"" + "a" * 200_000 + "\",login,203.0.113.9\n",                  # sel CSV raksasa
    '{"timestamp":"0001-01-01T00:00:00","event_type":"flow","src_ip":"203.0.113.9","dest_ip":"192.0.2.21","dest_port":22}',
    "waktu,jenis,sumber,aset,berhasil\n0001-01-01T00:00:00,login,203.0.113.9,ssh,tidak\n",
], ids=["json-bersarang", "csv-sel-raksasa", "json-tahun-0001", "csv-tahun-0001"])
def test_masukan_ganjil_berakhir_galat_impor_bukan_galat_500(k, isi):
    with pytest.raises(GalatImpor):
        baca(isi, SIMPUL)
    r = k.post("/api/deteksi/impor", headers=masuk(k), json={"nama": "aneh.log", "isi": isi})
    assert r.status_code == 422


def test_berkas_diurai_di_luar_kunci_keadaan(k, monkeypatch):
    """Berkas besar tidak boleh menahan dasbor layar lain: penguraian berjalan tanpa memegang kunci keadaan."""
    asli, saat_urai = main.MENARA.urai_log, []
    def urai(*a, **kw):
        saat_urai.append(main._kunci_state.locked())
        return asli(*a, **kw)
    monkeypatch.setattr(main.MENARA, "urai_log", urai)
    assert impor(k, masuk(k), "auth.log").status_code == 200
    assert saat_urai == [False]


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
