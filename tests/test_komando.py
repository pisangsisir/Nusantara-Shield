"""
Uji v5.1 — Pre-Authorized Containment + laporan otomatis ke manajemen (simulasi).
Prinsip yang diuji:
- Isolasi TIDAK menunggu izin: operator tim insiden bisa langsung menekan SOAR
  (Fase 4: peladen mengamankan bukti lebih dulu, ≈1,2 detik, baru memutus jaringan).
- Laporan otomatis terbit setelah SEMUA tindakan pemutus selesai (Fase 1, F-02).
- Quick Call hanya ke PIC teknis cabang (koordinasi agar server tidak di-restart).
Semua label dibaca dari app.istilah, sehingga mengganti istilah tidak memecahkan uji (F-01).
"""

import re

import pytest
from fastapi.testclient import TestClient

from app import main
from app.audit import LOG
from app.istilah import ISTILAH, nama_manajemen, pesan_jangan_restart
from app.keamanan import PEMBATAS

POLA_NOMOR = re.compile(rf"{re.escape(ISTILAH['laporan_singkat'])}-\d{{4}}-(\d{{3,}})")


def urut(nomor: str) -> int:
    return int(POLA_NOMOR.fullmatch(nomor).group(1))

JAM = {"t": 9000.0}


@pytest.fixture(autouse=True)
def bersihkan():
    PEMBATAS.reset()
    main.LAYANAN = main.salin_layanan_awal()
    JAM["t"] = 9000.0
    main.MENARA._jam = lambda: JAM["t"]
    main.MENARA.reset()
    main.MENARA.osint.berikut = 1e12
    yield


@pytest.fixture
def klien():
    return TestClient(main.app)


def masuk(klien, nama="operator", sandi="sandi-operator-uji-123"):
    j = klien.post("/api/login", json={"nama": nama, "sandi": sandi}).json()
    return {"Authorization": f"Bearer {j['token']}"}


def komando(klien, h, lid):
    return klien.get("/api/telemetri", headers=h).json()["komando"][lid]


def panggil(klien, h, lid):
    return klien.post("/api/komando/panggil", headers=h, json={"layanan_id": lid})


def picu(klien, h, lid, skenario):
    return klien.post("/api/simulasi", headers=h, json={"layanan_id": lid, "skenario": skenario})


def soar(klien, h, lid, aksi):
    return klien.post("/api/soar/jalankan", headers=h, json={"layanan_id": lid, "aksi": aksi})


# ---------- akses & validasi ----------
def test_quick_call_wajib_login_dan_hanya_operator(klien):
    data = {"layanan_id": "pajak"}
    assert klien.post("/api/komando/panggil", json=data).status_code == 401
    h = masuk(klien, "pengamat", "sandi-pengamat-uji-123")
    assert klien.post("/api/komando/panggil", headers=h, json=data).status_code == 403


@pytest.mark.parametrize("data", [
    {"layanan_id": "tidak-ada"},
    {"layanan_id": "pajak", "pic_id": "pimpinan"},
    {"layanan_id": "pajak", "nomor": "08123"},
])
def test_quick_call_menolak_input_aneh(klien, data):
    assert klien.post("/api/komando/panggil", headers=masuk(klien), json=data).status_code == 422


@pytest.mark.parametrize("jalur", ["/api/komando/izin", "/api/komando/panggil-aman"])
def test_loket_izin_lama_sudah_tidak_ada(klien, jalur):
    assert klien.post(jalur, headers=masuk(klien), json={"layanan_id": "pajak"}).status_code in (404, 405)


# ---------- data korporat ----------
@pytest.mark.parametrize("lid,kunci_jabatan,cabang", [
    ("imigrasi", "pic_cabang_utama", "RSPAD Gatot Soebroto, Jakarta"),
    ("pajak", "pic_basis_data", "Markas Utama Surabaya"),
    ("kesehatan", "pic_cabang", "RS Kesdam Makassar"),
])
def test_setiap_aset_punya_pic_teknis_cabang(klien, lid, kunci_jabatan, cabang):
    h = masuk(klien)
    k = komando(klien, h, lid)
    assert k["pic"]["jabatan"] == ISTILAH[kunci_jabatan] and k["pic"]["cabang"] == cabang
    assert k["ir"] is None and k["panggilan"] == []


def test_manajemen_hanya_penerima_ir(klien):
    m = klien.get("/api/telemetri", headers=masuk(klien)).json()["manajemen"]
    assert [x["jabatan"] for x in m] == nama_manajemen()


def test_titik_topologi_menunjuk_aset_pemilik(klien):
    h = masuk(klien)
    s = {x["id"]: x for x in klien.get("/api/telemetri", headers=h).json()["topologi"]["simpul"]}
    assert s["ssh"]["layanan"] == "logistik" and s["smb"]["layanan"] == "kesehatan" and s["fw"]["layanan"] is None
    picu(klien, h, "kesehatan", "ddos")
    s = {x["id"]: x for x in klien.get("/api/telemetri", headers=h).json()["topologi"]["simpul"]}
    assert s["fw"]["layanan"] == "kesehatan" and s["ancaman"]["layanan"] == "kesehatan"


# ---------- pre-authorized containment + IR blast ----------
def test_isolasi_langsung_tanpa_izin_dan_ir_terkirim_otomatis(klien):
    h = masuk(klien)
    picu(klien, h, "kesehatan", "ddos")
    JAM["t"] += 4
    r = soar(klien, h, "kesehatan", "isolasi")           # tanpa telepon/izin apa pun sebelumnya
    assert r.status_code == 200
    j = r.json()                                         # Fase 4: bukti diamankan dulu, pemutus menyusul
    assert j["dijadwalkan"] == ["amankan_bukti", "blokir_ip"] and j["ir"] is None and j["ir_menunggu"] is True
    JAM["t"] += 1.3
    ir = komando(klien, h, "kesehatan")["ir"]
    assert POLA_NOMOR.fullmatch(ir["nomor"]) and len(ir["uuid"]) == 32 and ir["keparahan"] == "SEV-1"
    assert ir["kepada"] == nama_manajemen() and ir["tindakan"] == ["Blokir IP anomali"]
    assert ir["rincian"] == [{"id": "blokir_ip", "label": "Blokir IP anomali", "status": "selesai",
                              "metode": "soar", "detik": 5}]
    assert ir["detik"] == 5 and ir["cabang"] == "RS Kesdam Makassar"
    assert ir["bukti"]["nomor"].startswith("BB-") and len(ir["bukti"]["sha256"]) == 64 and ir["darurat"] is None
    k = klien.get("/api/telemetri", headers=h).json()
    assert k["komando"]["kesehatan"]["ir"]["nomor"] == ir["nomor"] and k["ir"][0]["nomor"] == ir["nomor"]
    assert any(p["jenis"] == "ir" and ir["nomor"] in p["pesan"] for p in k["peristiwa"])
    ins = next(l for l in k["layanan"] if l["id"] == "kesehatan")["insiden"]
    assert ins["langkah_selesai"][3] is True             # langkah "LAPOR" tercentang otomatis
    assert {(c["dari"], c["ke"]): c["status"] for c in k["topologi"]["kabel"]}[("ancaman", "internet")] == "putus"
    # laporan diaudit pada detik ia lahir, lengkap dengan rujukan bukti
    e = next(e for e in LOG.daftar(10) if e["aksi"] == "IR_OTOMATIS" and e["detail"]["nomor"] == ir["nomor"])
    assert e["detail"]["bukti"] == ir["bukti"]["nomor"] and e["detail"]["darurat_alasan"] is None


def test_tindakan_bukan_pemutus_tidak_mengirim_ir(klien):
    h = masuk(klien)
    picu(klien, h, "kesehatan", "ddos")
    r = soar(klien, h, "kesehatan", "mode_hemat")
    assert r.status_code == 200 and r.json()["ir"] is None
    assert komando(klien, h, "kesehatan")["ir"] is None


def test_keparahan_ir_mengikuti_insiden_dan_nomor_berurutan(klien):
    h = masuk(klien)
    picu(klien, h, "pajak", "backup_dimatikan")
    picu(klien, h, "logistik", "ransomware")
    assert soar(klien, h, "pajak", "amankan_bukti").status_code == 200
    a = soar(klien, h, "pajak", "cabut_akses").json()["ir"]
    r = soar(klien, h, "logistik", "isolasi").json()
    assert r["ir"] is None and r["ir_menunggu"] is True   # pemutus masih antre di belakang bukti
    JAM["t"] += 2.6
    b = komando(klien, h, "logistik")["ir"]
    assert a["keparahan"] == "SEV-2" and b["keparahan"] == "SEV-1"
    assert urut(b["nomor"]) == urut(a["nomor"]) + 1


# ---------- quick call ----------
def test_quick_call_ke_admin_cabang_memberi_tahu_isolasi(klien):
    h = masuk(klien)
    assert panggil(klien, h, "kesehatan").json()["pesan"] == "koordinasi rutin"
    picu(klien, h, "kesehatan", "ddos")
    soar(klien, h, "kesehatan", "amankan_bukti")
    soar(klien, h, "kesehatan", "blokir_ip")
    j = panggil(klien, h, "kesehatan").json()
    assert j["jabatan"] == ISTILAH["pic_cabang"] and j["pesan"] == pesan_jangan_restart()
    k = klien.get("/api/telemetri", headers=h).json()
    assert k["komando"]["kesehatan"]["panggilan"][0]["pesan"] == j["pesan"]
    assert any(p["jenis"] == "komando" and ISTILAH["quick_call"] in p["pesan"] for p in k["peristiwa"])
    assert LOG.daftar(1)[0]["aksi"] == "QUICK_CALL"


def test_ir_gugur_saat_insiden_ditutup(klien):
    h = masuk(klien)
    picu(klien, h, "pajak", "backup_dimatikan")
    soar(klien, h, "pajak", "isolasi")
    JAM["t"] += 5
    for i in range(1, 6):                                # langkah 1 (bukti) sudah oleh isolasi
        klien.post("/api/playbook/langkah", headers=h, json={"layanan_id": "pajak", "indeks": i, "selesai": True})
    assert klien.post("/api/pulihkan", headers=h, json={"layanan_id": "pajak"}).status_code == 200
    assert komando(klien, h, "pajak")["ir"] is None


# ---------- Fase 1: integritas laporan & pemisahan isolasi/pemulihan ----------
def test_laporan_hanya_terbit_setelah_semua_pemutus_selesai(klien):
    h = masuk(klien)
    picu(klien, h, "kesehatan", "ransomware")
    r = soar(klien, h, "kesehatan", "isolasi").json()
    assert r["ir"] is None and r["ir_menunggu"] is True
    assert komando(klien, h, "kesehatan")["ir"] is None           # baru bukti; pemutus masih antre
    JAM["t"] += 1.3
    assert komando(klien, h, "kesehatan")["ir"] is None           # "Amankan cadangan" masih antre
    JAM["t"] += 1.3
    ir = komando(klien, h, "kesehatan")["ir"]
    assert [(x["id"], x["status"], x["metode"], x["detik"]) for x in ir["rincian"]] == [
        ("isolasi_otomatis", "selesai", "soar", 1), ("amankan_backup", "selesai", "soar", 3)]
    assert any(e["aksi"] == "IR_OTOMATIS" and e["detail"]["nomor"] == ir["nomor"] for e in LOG.daftar(3))


def test_isolasi_manual_juga_menerbitkan_laporan_tepat_sekali(klien):
    h = masuk(klien)
    picu(klien, h, "pajak", "ransomware")
    for i in (0, 1, 2):                                  # bukti, isolasi, amankan backup — semuanya manual
        assert klien.post("/api/playbook/langkah", headers=h,
                          json={"layanan_id": "pajak", "indeks": i, "selesai": True}).status_code == 200
    ir = komando(klien, h, "pajak")["ir"]
    assert ir and [x["metode"] for x in ir["rincian"]] == ["manual", "manual"] and ir["bukti"]
    jumlah = sum(1 for e in LOG.daftar(50) if e["aksi"] == "IR_OTOMATIS" and e["detail"]["nomor"] == ir["nomor"])
    assert jumlah == 1


def test_pulihkan_terkunci_sampai_terisolasi_dan_playbook_dicentang(klien):
    h = masuk(klien)
    picu(klien, h, "kesehatan", "ddos")
    r = soar(klien, h, "kesehatan", "pulihkan")
    assert r.status_code == 409 and "Belum terisolasi" in r.json()["detail"]
    centang = lambda i: klien.post("/api/playbook/langkah", headers=h,
                                   json={"layanan_id": "kesehatan", "indeks": i, "selesai": True})
    assert centang(5).status_code == 409                          # jalan pintas manual juga terkunci
    soar(klien, h, "kesehatan", "isolasi")
    JAM["t"] += 1.3                                               # bukti → pemutus → laporan
    r = soar(klien, h, "kesehatan", "pulihkan")
    assert r.status_code == 409 and "3, 5" in r.json()["detail"]  # langkah 3 & 5 (nomor manusia) belum
    syarat = klien.get("/api/telemetri", headers=h).json()["soar"]["syarat_pulih"]["kesehatan"]
    assert syarat and "3, 5" in syarat
    centang(2), centang(4)
    assert soar(klien, h, "kesehatan", "pulihkan").status_code == 200
    ins = next(l for l in klien.get("/api/telemetri", headers=h).json()["layanan"] if l["id"] == "kesehatan")
    assert ins["insiden"]["langkah_selesai"][5] is True


def test_aksi_semua_lama_sudah_ditolak(klien):
    h = masuk(klien)
    picu(klien, h, "pajak", "ransomware")
    assert soar(klien, h, "pajak", "semua").status_code == 422


def test_nomor_laporan_tidak_berulang_setelah_reset(klien):
    h = masuk(klien)
    nomor = []
    for _ in range(2):
        picu(klien, h, "kesehatan", "ddos")
        soar(klien, h, "kesehatan", "isolasi")
        JAM["t"] += 1.3
        nomor.append(komando(klien, h, "kesehatan")["ir"])
        assert klien.post("/api/reset-demo", headers=h).status_code == 200
    assert urut(nomor[1]["nomor"]) == urut(nomor[0]["nomor"]) + 1
    assert nomor[0]["uuid"] != nomor[1]["uuid"]


def test_penomoran_persisten_melewati_restart(tmp_path):
    from app.penomoran import PencacahIR
    berkas = tmp_path / "nomor_ir.json"
    a, _ = PencacahIR(berkas).berikutnya("IR")
    b, _ = PencacahIR(berkas).berikutnya("IR")                    # objek baru = server dinyalakan ulang
    assert urut_bebas(b) == urut_bebas(a) + 1


def urut_bebas(nomor: str) -> int:
    return int(nomor.rsplit("-", 1)[1])
