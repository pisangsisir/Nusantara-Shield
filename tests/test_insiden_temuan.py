# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
Uji v5.4.2: Operator membuka insiden LANGSUNG dari temuan log asli (impor berkas).

Prinsip yang dikunci:
- Membuka insiden adalah keputusan Operator: impor saja tetap hanya menaikkan WASPADA (lihat test_impor_log.py).
- Insiden dari temuan tidak memuat perangkat, alamat, atau kronologi rekaan: aset terdampak = aset temuan,
  kronologi = temuan itu sendiri, label ATT&CK = aturan temuan.
- Doktrin sesudahnya sama persis dengan latihan: bukti dulu, baru putus, tombol ditahan, laporan setelah pemutus.
- Hanya temuan impor yang aktif, belum ditutup, dan asetnya punya layanan pemilik; satu insiden per layanan.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import main
from app.audit import LOG
from app.keamanan import PEMBATAS

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


def impor(k, h, berkas):
    r = k.post("/api/deteksi/impor", headers=h, json={"nama": berkas, "isi": (CONTOH / berkas).read_text(encoding="utf-8")})
    assert r.status_code == 200, r.text
    return {t["aturan"]: t for t in r.json()["temuan"]}


def potret(k, h):
    return k.get("/api/telemetri", headers=h).json()


def peringatan(k, h, tid):
    return next(x for x in potret(k, h)["peringatan"] if x["id"] == tid)


def buka(k, h, tid):
    return k.post("/api/insiden/dari-temuan", headers=h, json={"temuan_id": tid})


def test_impor_saja_tidak_membuka_insiden_tetapi_mengusulkannya(k):
    h = masuk(k)
    tm = impor(k, h, "auth.log")["login_tembus"]
    assert not any(l["insiden"] for l in main.LAYANAN.values())
    usul = peringatan(k, h, tm["id"])["usul_insiden"]
    assert usul["layanan_id"] == "logistik" and usul["skenario"] == "intrusi_log" and usul["aset"] == ["ssh"]


def test_insiden_dari_temuan_memakai_aset_dan_kronologi_temuan_bukan_templat(k):
    h = masuk(k)
    tm = impor(k, h, "auth.log")["login_tembus"]
    r = buka(k, h, tm["id"])
    assert r.status_code == 200, r.text
    ins = r.json()["insiden"]
    assert ins["skenario"] == "intrusi_log" and ins["temuan"]["id"] == tm["id"]
    assert ins["temuan"]["berkas"] == "auth.log" and ins["temuan"]["aset"] == ["ssh"]
    assert list(ins["dampak"]["perangkat"]) == ["ssh"] and ins["dampak"]["ancaman"] == []
    assert len(ins["log_peringatan"]) == 1 and "auth.log" in ins["log_peringatan"][0]["pesan"]
    assert tm["id"] in ins["log_peringatan"][0]["pesan"]
    JAM["t"] += 5
    status = {s["id"]: s["status"] for s in potret(k, h)["topologi"]["simpul"]}
    assert status["ssh"] == "kritis"
    assert status["smb"] == "normal" and status["backup"] == "normal"      # tidak ada perangkat rekaan
    e = LOG.daftar(5)[0]
    assert e["aksi"] == "INSIDEN_DARI_TEMUAN" and e["detail"]["temuan"] == tm["id"] and e["detail"]["layanan"] == "logistik"


def test_label_attck_insiden_mengikuti_aturan_temuan(k):
    h = masuk(k)
    tm = impor(k, h, "auth.log")["login_tembus"]
    buka(k, h, tm["id"])
    x = peringatan(k, h, "ins-logistik")
    assert [m["id"] for m in x["mitre"]] == [m["id"] for m in tm["mitre"]] == ["T1078", "T1110"]


def test_doktrin_sama_bukti_dulu_baru_putus_lalu_aset_temuan_terisolasi(k):
    h = masuk(k)
    tm = impor(k, h, "auth.log")["login_tembus"]
    buka(k, h, tm["id"])
    r = k.post("/api/soar/jalankan", headers=h, json={"layanan_id": "logistik", "aksi": "isolasi"})
    assert r.status_code == 200, r.text
    for _ in range(10):
        JAM["t"] += 1.5
        potret(k, h)
    p = potret(k, h)
    assert {s["id"]: s["status"] for s in p["topologi"]["simpul"]}["ssh"] == "isolasi"
    bukti = next(e for e in main.MENARA.rantai.daftar(10) if e["aksi"] == "BUKTI_DIAMANKAN")
    asli = bukti["detail"]["sumber_temuan"]                             # berkas log asli: SHA-256 sungguhan
    import hashlib
    assert asli["berkas"] == "auth.log" and asli["id"] == tm["id"]
    assert asli["sha256_berkas"] == hashlib.sha256((CONTOH / "auth.log").read_bytes()).hexdigest()
    ins = main.LAYANAN["logistik"]["insiden"]
    assert ins["langkah_selesai"][0] and ins["langkah_selesai"][1]     # bukti, lalu isolasi


def test_temuan_ot_memakai_playbook_sabotase_ot_dan_hanya_genset(k):
    h = masuk(k)
    tm = impor(k, h, "suricata-eve.json")["tulis_ot_luar_jadwal"]
    r = buka(k, h, tm["id"])
    assert r.status_code == 200, r.text
    ins = r.json()["insiden"]
    assert r.json()["id"] == "listrik" and ins["skenario"] == "sabotase_ot"
    assert list(ins["dampak"]["perangkat"]) == ["genset"]
    assert all(set(e["perangkat"]) <= {"genset"} for e in ins["dampak"]["langkah"].values())


def test_penolakan_peran_temuan_tak_dikenal_latihan_ganda_dan_ditutup(k):
    h = masuk(k)
    tm = impor(k, h, "auth.log")
    assert buka(k, masuk(k, "pengamat", "sandi-pengamat-uji-123"), tm["login_tembus"]["id"]).status_code == 403
    assert buka(k, h, "DET-999").status_code == 404
    assert k.post("/api/insiden/dari-temuan", headers=h, json={"temuan_id": "../x"}).status_code == 422
    assert buka(k, h, tm["login_tembus"]["id"]).status_code == 200
    r = buka(k, h, tm["login_gagal"]["id"])                      # layanan yang sama sudah dalam insiden
    assert r.status_code == 409 and "sudah dalam insiden" in r.json()["detail"]
    # temuan latihan (bukan log asli) tidak bisa dibuka menjadi insiden
    k.post("/api/deteksi/latihan", headers=h, json={"jenis": "pindai_port"})
    for _ in range(40):
        JAM["t"] += 1
        potret(k, h)
    latihan = [t for t in main.MENARA.deteksi.temuan if t.asal != "impor"]
    assert latihan
    r = buka(k, h, latihan[-1].id)
    assert r.status_code == 409 and "log asli" in r.json()["detail"]


def test_temuan_yang_ditutup_lewat_triase_tidak_bisa_dibuka(k):
    h = masuk(k)
    tm = impor(k, h, "auth.log")["login_tembus"]
    r = k.post("/api/peringatan/tutup", headers=h, json={"aset_id": "ssh", "status": "false_positive",
                                                          "alasan": "Uji penetrasi resmi oleh tim jaringan satuan"})
    assert r.status_code == 200, r.text
    r = buka(k, h, tm["id"])
    assert r.status_code == 409 and "ditutup" in r.json()["detail"]
    assert peringatan(k, h, tm["id"])["usul_insiden"] is None


def test_skenario_intrusi_log_tidak_bisa_dipicu_lewat_simulasi(k):
    h = masuk(k)
    r = k.post("/api/simulasi", headers=h, json={"layanan_id": "logistik", "skenario": "intrusi_log"})
    assert r.status_code == 422


def test_insiden_dari_temuan_bisa_dipulihkan_dan_layanan_normal_kembali(k):
    h = masuk(k)
    tm = impor(k, h, "auth.log")["login_tembus"]
    buka(k, h, tm["id"])
    k.post("/api/soar/jalankan", headers=h, json={"layanan_id": "logistik", "aksi": "isolasi"})
    for _ in range(10):
        JAM["t"] += 1.5
        potret(k, h)
    k.post("/api/playbook/langkah", headers=h, json={"layanan_id": "logistik", "indeks": 2, "selesai": True})
    r = k.post("/api/soar/jalankan", headers=h, json={"layanan_id": "logistik", "aksi": "pulihkan"})
    assert r.status_code == 200, r.text
    for i in range(len(main.LAYANAN["logistik"]["insiden"]["langkah"])):
        k.post("/api/playbook/langkah", headers=h, json={"layanan_id": "logistik", "indeks": i, "selesai": True})
    r = k.post("/api/pulihkan", headers=h, json={"layanan_id": "logistik"})
    assert r.status_code == 200, r.text
    assert main.LAYANAN["logistik"]["insiden"] is None


def test_lapsit_menyebut_asal_temuan_dan_sha256_berkas(k):
    import hashlib
    import re
    h = masuk(k)
    tm = impor(k, h, "auth.log")["login_tembus"]
    buka(k, h, tm["id"])
    r = k.post("/api/lapsit", headers=h)
    assert r.status_code == 200
    import importlib.util
    spec = importlib.util.spec_from_file_location("_tp", Path(__file__).with_name("test_titik_periksa.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    teks = re.sub(r"\s+", "", m.teks_pdf(r.content))
    assert "membukainsidendaritemuanlogasli" in teks and "Asal:temuanlogasli" in teks and tm["id"] in teks and "auth.log" in teks
    sidik = hashlib.sha256((CONTOH / "auth.log").read_bytes()).hexdigest()
    assert sidik in teks


def test_temuan_drill_bukan_log_asli_dan_tidak_bisa_dibuka(k):
    h = masuk(k)
    r = k.post("/api/drill/mulai", headers=h, json={"kode": "cadangan_dilepas"})
    assert r.status_code == 200, r.text
    drill = [t for t in main.MENARA.deteksi.temuan if t.drill]
    assert drill and all(peringatan(k, h, t.id)["usul_insiden"] is None for t in drill
                         if any(x["id"] == t.id for x in potret(k, h)["peringatan"]))
    r = buka(k, h, drill[0].id)
    assert r.status_code == 409 and "Drill" in r.json()["detail"]


def test_satu_temuan_paling_banyak_satu_insiden(k):
    h = masuk(k)
    tm = impor(k, h, "auth.log")["login_tembus"]
    assert buka(k, h, tm["id"]).status_code == 200
    main.LAYANAN["logistik"]["insiden"] = None                            # seolah sudah dipulihkan dan ditutup
    r = buka(k, h, tm["id"])
    assert r.status_code == 409 and "sudah pernah dibuka" in r.json()["detail"]


def test_judul_waktu_dan_teks_insiden_ot_tidak_memakai_templat(k):
    h = masuk(k)
    tm = impor(k, h, "suricata-eve.json")["ot_tanpa_izin"]
    ins = buka(k, h, tm["id"]).json()["insiden"]
    assert "Modbus asing" not in ins["judul"] and tm["nama"] in ins["judul"]
    waktu_temuan = peringatan(k, h, tm["id"])["waktu"]
    assert ins["log_peringatan"][0]["waktu"] == waktu_temuan               # waktu kejadian, bukan saat dibuka
    from app.lapsit import dampak_operasional
    teks = dampak_operasional(main.LAYANAN["listrik"], None)
    assert "jadwal start genset" not in teks and tm["nama"].lower() in teks
    k.post("/api/soar/jalankan", headers=h, json={"layanan_id": "listrik", "aksi": "amankan_bukti"})
    bukti = next(e for e in main.MENARA.rantai.daftar(10) if e["aksi"] == "BUKTI_DIAMANKAN")
    assert "log_workstation_teknisi.evtx" not in {b["nama"] for b in bukti["detail"]["barang"]}


def test_isolasi_insiden_dari_temuan_tanpa_tahan_ditolak(k):
    h = masuk(k)
    tm = impor(k, h, "auth.log")["login_tembus"]
    buka(k, h, tm["id"])
    r = k.post("/api/soar/jalankan", headers=h, json={"layanan_id": "logistik", "aksi": "isolasi", "tahan": None})
    assert r.status_code == 428
