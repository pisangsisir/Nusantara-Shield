"""
Uji Mesin Deteksi Aturan (app/deteksi.py): login gagal berulang, login tembus, dan pemindaian port.

Prinsip yang dikunci:
- Temuan lahir dari HITUNGAN peristiwa mentah dengan ambang terbuka, bukan dari baris log yang disuntikkan.
  Di bawah ambang, di luar jendela waktu, atau port yang sama berulang: TIDAK ada temuan.
- Temuan hanya menaikkan peluang serangan (Kunci 1, mesin). Tidak ada insiden, isolasi, atau tindakan SOAR
  yang dipicu olehnya; memutus jaringan tetap keputusan Operator (Kunci 2).
- Temuan ikut aturan yang sama dengan CTI dan AI: Perketat memotong paparan, triase menutupnya beralasan,
  temuan kedaluwarsa, dan episode baru membuka peringatan lagi.
- Daftar peringatan menulis siapa Operator yang mengisolasi dan nomor berita acara bukti yang sebenarnya.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import main
from app.deteksi import ATURAN, AWALAN, MASA_AKTIF, MesinDeteksi
from app.keamanan import PEMBATAS

JAM = {"t": 9000.0}


@pytest.fixture(autouse=True)
def bersihkan():
    PEMBATAS.reset()
    main.LAYANAN = main.salin_layanan_awal()
    JAM["t"] = 9000.0
    main.MENARA._jam = lambda: JAM["t"]
    main.MENARA.reset()
    main.MENARA.osint.berikut = 1e12        # matikan siaran CTI otomatis: uji yang menentukan


@pytest.fixture
def k():
    return TestClient(main.app)


def masuk(k, nama="operator", sandi="sandi-operator-uji-123"):
    j = k.post("/api/login", json={"nama": nama, "sandi": sandi}).json()
    return {"Authorization": f"Bearer {j['token']}"}


def potret(k, h):
    return k.get("/api/telemetri", headers=h).json()


def prediksi(p):
    return {x["id"]: x for x in p["cti"]["prediksi"]}


def latih(k, h, jenis, aset_id=None, maju=30):
    data = {"jenis": jenis} | ({"aset_id": aset_id} if aset_id else {})
    r = k.post("/api/deteksi/latihan", headers=h, json=data)
    assert r.status_code == 200, r.text
    JAM["t"] += maju
    return r.json()


def gagal(m, t, sumber="203.0.113.77", aset="ssh"):
    return m.proses({"jenis": "login", "sumber": sumber, "aset": aset, "berhasil": False}, t)


def konek(m, t, ip, port, sumber="198.51.100.66", aset=None):
    return m.proses({"jenis": "koneksi", "sumber": sumber, "ip": ip, "port": port, "aset": aset}, t)


# ---------------------------------------------------------------- aturan (unit, tanpa server)
def test_ambang_terbuka_sesuai_dokumentasi():
    """Angka ini tertulis di Dokumentasi Teknis; mengubahnya wajib mengubah dokumen juga."""
    assert (ATURAN["login_gagal"]["ambang"], ATURAN["login_gagal"]["jendela"]) == (8, 60)
    assert (ATURAN["pindai_port"]["ambang"], ATURAN["pindai_port"]["jendela"]) == (15, 10)
    assert ATURAN["login_tembus"]["jendela"] == 120 and MASA_AKTIF == 300
    assert {a: ATURAN[a]["peluang"] for a in ATURAN} == {"login_gagal": 0.60, "login_tembus": 0.85, "pindai_port": 0.35,
                                                         "ot_tanpa_izin": 0.50, "tulis_ot_luar_jadwal": 0.70,
                                                         "rantai_it_ot": 0.90}


def test_temuan_muncul_tepat_pada_gagal_kedelapan(k):
    h = masuk(k)
    k.post("/api/deteksi/latihan", headers=h, json={"jenis": "login_gagal"})   # gagal ke-n tiba di detik 2n − 1
    JAM["t"] += 14.0                                                         # baru 7 kali gagal
    assert "ssh" not in prediksi(potret(k, h))
    JAM["t"] += 1.0                                                          # gagal ke-8 → temuan
    assert prediksi(potret(k, h))["ssh"]["proaktif"]


def test_login_gagal_ambang_tepat():
    m, n = MesinDeteksi(), ATURAN["login_gagal"]["ambang"]
    for i in range(n - 1):
        assert gagal(m, i * 2.0) == []                     # 7 kali gagal: belum mencurigakan
    baru = gagal(m, (n - 1) * 2.0)
    assert len(baru) == 1 and baru[0].aturan == "login_gagal" and baru[0].id.startswith(AWALAN)
    assert baru[0].jumlah == n and baru[0].keparahan == "sedang"


def test_login_gagal_tersebar_di_luar_jendela_tidak_memicu():
    m = MesinDeteksi()
    jarak = ATURAN["login_gagal"]["jendela"] / (ATURAN["login_gagal"]["ambang"] - 1) + 1   # ≈9,6 dtk
    assert all(gagal(m, i * jarak) == [] for i in range(20))
    assert m.temuan == []


def test_rentetan_berlanjut_tidak_menggandakan_temuan():
    m = MesinDeteksi()
    temuan = [x for i in range(12) for x in gagal(m, i * 2.0)]
    assert len(temuan) == 1 and m.temuan[0].jumlah == 12


def test_login_berhasil_setelah_rentetan_gagal_menjadi_tinggi():
    m = MesinDeteksi()
    for i in range(8):
        gagal(m, i * 2.0)
    lain = m.proses({"jenis": "login", "sumber": "192.0.2.150", "aset": "ssh", "berhasil": True}, 17.0)
    assert lain == []                                       # sumber lain yang login wajar: bukan temuan
    tembus = m.proses({"jenis": "login", "sumber": "203.0.113.77", "aset": "ssh", "berhasil": True}, 20.0)
    assert len(tembus) == 1 and tembus[0].aturan == "login_tembus" and tembus[0].keparahan == "tinggi"
    assert m.proses({"jenis": "login", "sumber": "203.0.113.77", "aset": "ssh", "berhasil": True}, 21.0) == []


def test_login_berhasil_tanpa_rentetan_bukan_temuan():
    m = MesinDeteksi()
    assert m.proses({"jenis": "login", "sumber": "192.0.2.150", "aset": "ssh", "berhasil": True}, 1.0) == []


def test_pindai_port_ambang_kombinasi_berbeda():
    m, n = MesinDeteksi(), ATURAN["pindai_port"]["ambang"]
    for p in range(n - 1):
        assert konek(m, p * 0.2, "192.0.2.10", 1000 + p) == []
    baru = konek(m, (n - 1) * 0.2, "192.0.2.10", 443, aset="portal")
    assert len(baru) == 1 and baru[0].aturan == "pindai_port" and baru[0].aset == ["portal"]


def test_port_sama_berulang_bukan_pemindaian():
    m = MesinDeteksi()
    assert all(konek(m, i * 0.1, "192.0.2.10", 443, aset="portal") == [] for i in range(60))


def test_pindai_lambat_di_luar_jendela_tidak_memicu():
    m = MesinDeteksi()
    assert all(konek(m, i * 1.0, "192.0.2.10", 2000 + i) == [] for i in range(40))   # ≤ 11 per 10 dtk


def test_modul_deteksi_tidak_menyentuh_jaringan():
    sumber = Path(main.__file__).with_name("deteksi.py").read_text(encoding="utf-8")
    for terlarang in ("import socket", "import urllib", "import requests", "import httpx", "subprocess"):
        assert terlarang not in sumber


# ---------------------------------------------------------------- terpadu (lewat server)
def test_latihan_login_gagal_menaikkan_waspada_tanpa_memutus(k):
    h = masuk(k)
    r = k.post("/api/deteksi/latihan", headers=h, json={"jenis": "login_gagal"})
    assert r.status_code == 200 and r.json()["aset_id"] == "ssh" and r.json()["peristiwa"] == 13
    assert "ssh" not in prediksi(potret(k, h))              # peristiwa belum tiba: belum ada temuan
    JAM["t"] += 30
    p = potret(k, h)
    ssh = prediksi(p)["ssh"]
    assert ssh["proaktif"] and ssh["persen"] == 60 and ssh["sumber"][0].startswith(AWALAN)
    assert ssh["deteksi"][0]["nama"] == ATURAN["login_gagal"]["nama"] and "12 login gagal" in ssh["deteksi"][0]["alasan"]
    # Kunci 2: tidak ada insiden, isolasi, atau antrean SOAR
    assert not any(l["insiden"] for l in main.LAYANAN.values())
    assert main.MENARA._antre_soar == []
    assert any(e["jenis"] == "deteksi" and e["tingkat"] == "sedang" and "Deteksi ▶" in e["pesan"] for e in p["peristiwa"])
    pr = [x for x in p["peringatan"] if x["jenis"] == "deteksi"][0]
    assert pr["status"] == "Aset dinaikkan ke WASPADA" and pr["keparahan"] == "sedang"


def test_login_tembus_lebih_genting(k):
    h = masuk(k)
    latih(k, h, "login_tembus")
    ssh = prediksi(potret(k, h))["ssh"]
    assert {d["keparahan"] for d in ssh["deteksi"]} == {"sedang", "tinggi"}
    assert ssh["persen"] == round((1 - (1 - 0.60) * (1 - 0.85)) * 100)    # 94%


def test_pindai_port_menyentuh_aset_dmz_yang_terbuka(k):
    h = masuk(k)
    latih(k, h, "pindai_port", maju=10)
    t = potret(k, h)["deteksi"]["temuan"][0]
    assert t["aturan"] == "pindai_port" and t["aset"] == ["api", "portal"] and t["keparahan"] == "tinggi"
    pr = prediksi(potret(k, h))
    assert pr["portal"]["persen"] == 35 and not pr["portal"]["proaktif"]     # pengintaian: dipantau, belum WASPADA
    assert "ssh" not in pr and "db" not in pr                               # aset internal tidak terjangkau dari luar


def test_perketat_memotong_sumbangan_deteksi(k):
    h = masuk(k)
    latih(k, h, "login_gagal")
    assert k.post("/api/soar/perketat", headers=h, json={"aset_id": "ssh"}).status_code == 200
    assert prediksi(potret(k, h))["ssh"]["persen"] == 18                  # 60% × 0,3


def test_triase_menutup_temuan_lalu_episode_baru_membuka_lagi(k):
    h = masuk(k)
    latih(k, h, "login_gagal")
    lama = prediksi(potret(k, h))["ssh"]["sumber"][0]
    r = k.post("/api/peringatan/tutup", headers=h,
               json={"aset_id": "ssh", "status": "false_positive", "alasan": "Teknisi salah ketik sandi saat pemeliharaan"})
    assert r.status_code == 200 and r.json()["sumber"] == [lama]
    p = potret(k, h)
    assert "ssh" not in prediksi(p)
    assert [x["status"] for x in p["peringatan"] if x["id"] == lama] == ["Ditutup lewat triase"]
    JAM["t"] += MASA_AKTIF + 10                                             # episode lama habis
    latih(k, h, "login_gagal")
    baru = prediksi(potret(k, h))["ssh"]
    assert baru["proaktif"] and baru["sumber"][0] != lama                  # bukti baru → peringatan terbuka lagi


def test_temuan_kedaluwarsa_setelah_masa_aktif(k):
    h = masuk(k)
    latih(k, h, "login_gagal")
    assert prediksi(potret(k, h))["ssh"]["proaktif"]
    JAM["t"] += MASA_AKTIF
    p = potret(k, h)
    assert "ssh" not in prediksi(p)
    assert [x["status"] for x in p["peringatan"] if x["jenis"] == "deteksi"] == ["Berakhir"]


def test_peringatan_isolasi_memakai_operator_dan_nomor_bukti_sebenarnya(k):
    h = masuk(k)
    assert k.post("/api/simulasi", headers=h, json={"layanan_id": "kesehatan", "skenario": "ransomware"}).status_code == 200
    ins = [x for x in potret(k, h)["peringatan"] if x["jenis"] == "insiden"][0]
    assert ins["status"] == "Menunggu keputusan Operator" and ins["keparahan"] == "kritis"
    JAM["t"] += 4
    assert k.post("/api/soar/jalankan", headers=h, json={"layanan_id": "kesehatan", "aksi": "isolasi"}).status_code == 200
    JAM["t"] += 3
    p = potret(k, h)
    nomor = p["forensik"]["insiden"]["kesehatan"]["bukti"]["nomor"]
    ins = [x for x in p["peringatan"] if x["jenis"] == "insiden"][0]
    assert ins["status"] == f"Diisolasi oleh operator · bukti {nomor}" and ins["kelas"] == "ditahan"
    # setelah ditutup, riwayat tetap menyebut siapa dan bukti mana
    main.LAYANAN["kesehatan"]["insiden"] = None
    main.MENARA.insiden_ditutup("kesehatan")
    pulih = [x for x in potret(k, h)["peringatan"] if x["jenis"] == "pulih"][0]
    assert pulih["status"] == f"Diisolasi oleh operator · bukti {nomor} · dipulihkan"


def test_temuan_pada_aset_dalam_insiden_berlabel_jujur(k):
    h = masuk(k)
    latih(k, h, "login_gagal")
    assert k.post("/api/simulasi", headers=h, json={"layanan_id": "kesehatan", "skenario": "ransomware"}).status_code == 200
    p = potret(k, h)                      # ransomware menyeret ssh ke dalam insiden
    det = [x for x in p["peringatan"] if x["jenis"] == "deteksi"][0]
    assert det["status"] == "Aset ditangani lewat playbook insiden"
    assert not prediksi(p).get("ssh", {}).get("proaktif")


@pytest.mark.parametrize("data", [
    {"jenis": "serang"}, {"jenis": "login_gagal", "aset_id": "tidak-ada"}, {"jenis": "pindai_port", "lain": 1}, {}])
def test_masukan_aneh_ditolak(k, data):
    assert k.post("/api/deteksi/latihan", headers=masuk(k), json=data).status_code == 422


def test_hanya_operator_yang_boleh_memutar_latihan(k):
    assert k.post("/api/deteksi/latihan", json={"jenis": "login_gagal"}).status_code == 401
    h = masuk(k, "pengamat", "sandi-pengamat-uji-123")
    assert k.post("/api/deteksi/latihan", headers=h, json={"jenis": "login_gagal"}).status_code == 403
