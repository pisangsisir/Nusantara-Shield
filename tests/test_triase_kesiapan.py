"""
Uji triase peringatan dan Nilai Kesiapan Siber.

Prinsip yang dikunci:
- Nilai Kesiapan Siber dihitung dengan rumus terbuka: dua sub-skor (Kerawanan, Insiden) per layanan,
  nilai = yang lebih rendah; posko = rata-rata tertimbang jumlah aset; huruf A–E.
- Selama ada insiden yang belum ditahan, nilai posko paling tinggi D.
- Hanya Operator yang boleh menutup peringatan WASPADA, wajib dengan alasan tertulis.
- Penutupan TIDAK menghapus apa pun: menjadi halaman baru di Buku Rantai Bukti (HMAC berantai) dan log audit;
  berita CTI tetap aktif; bukti baru membuka peringatan lagi.
"""

import pytest
from fastapi.testclient import TestClient

from app import main
from app.audit import LOG
from app.bukti import PERINGATAN_DITUTUP
from app.istilah import ISTILAH
from app.keamanan import PEMBATAS
from app.telemetri import PLAFON_INSIDEN_AKTIF, SUMBER_AI, huruf_nilai

JAM = {"t": 7000.0}


@pytest.fixture(autouse=True)
def bersihkan():
    PEMBATAS.reset()
    main.LAYANAN = main.salin_layanan_awal()
    JAM["t"] = 7000.0
    main.MENARA._jam = lambda: JAM["t"]
    main.MENARA.reset()
    main.MENARA.osint.berikut = 1e12        # matikan siaran CTI otomatis: uji yang menentukan


@pytest.fixture
def klien():
    return TestClient(main.app)


def masuk(klien, nama="operator", sandi="sandi-operator-uji-123"):
    j = klien.post("/api/login", json={"nama": nama, "sandi": sandi}).json()
    return {"Authorization": f"Bearer {j['token']}"}


def potret(klien, h):
    return klien.get("/api/telemetri", headers=h).json()


def siarkan(klien, h, berita_id):
    r = klien.post("/api/cti/siarkan", headers=h, json={"berita_id": berita_id})
    main.MENARA.osint.berikut = 1e12
    return r


def tutup(klien, h, aset_id, status="false_positive", alasan="Port Modbus genset hanya terbuka ke jaringan kendali lokal"):
    return klien.post("/api/peringatan/tutup", headers=h, json={"aset_id": aset_id, "status": status, "alasan": alasan})


def layanan(kesiapan, lid):
    return next(x for x in kesiapan["per_layanan"] if x["id"] == lid)


def prediksi(k):
    return {p["id"]: p for p in k["cti"]["prediksi"]}


# ---------- Nilai Kesiapan Siber ----------
def test_huruf_mengikuti_batas_terbuka():
    assert [huruf_nilai(x) for x in (100, 90, 89.9, 75, 60, 59, 40, 39, 0)] == list("AABBCDDEE")


def test_nilai_awal_mengikuti_rumus_terbuka(klien):
    k = potret(klien, masuk(klien))["kesiapan"]
    # Portal Alkes Kesdam: backup 52 jam > batas → Kerawanan 100 − 20 = 80 (B)
    assert (layanan(k, "perizinan")["kerawanan"], layanan(k, "perizinan")["insiden"], layanan(k, "perizinan")["huruf"]) == (80, 100, "B")
    # Genset RS Kesdam: RDP terbuka (temuan konfigurasi) pada 1 dari 2 aset → 100 − 30 × 1/2 = 85
    assert layanan(k, "listrik")["kerawanan"] == 85 and layanan(k, "listrik")["rincian"]["temuan"] == 1
    assert layanan(k, "imigrasi")["nilai"] == 100
    # Posko: rata-rata tertimbang jumlah aset (9 aset berport)
    bobot = sum(x["kerawanan"] * x["aset"] for x in k["per_layanan"]) / sum(x["aset"] for x in k["per_layanan"])
    assert abs(k["kerawanan"] - bobot) <= 1 and k["insiden"] == 100
    assert k["nilai"] == min(k["kerawanan"], k["insiden"]) and k["huruf"] == huruf_nilai(k["nilai"]) and k["batas"] is None


def test_kabar_ancaman_menurunkan_kedua_sub_skor_dan_perketat_memulihkannya(klien):
    h = masuk(klien)
    awal = layanan(potret(klien, h)["kesiapan"], "listrik")
    siarkan(klien, h, "CTI-109")                          # Modbus → genset ≈66% → WASPADA
    k = potret(klien, h)
    g = layanan(k["kesiapan"], "listrik")
    assert prediksi(k)["genset"]["proaktif"] and g["rincian"]["peringatan_terbuka"] == 1
    assert g["kerawanan"] < awal["kerawanan"] and g["insiden"] == 85 and g["huruf"] in "CD"
    klien.post("/api/soar/perketat", headers=h, json={"aset_id": "genset"})
    assert layanan(potret(klien, h)["kesiapan"], "listrik")["kerawanan"] > g["kerawanan"]


def test_perketat_menutup_temuan_konfigurasi(klien):
    h = masuk(klien)
    klien.post("/api/soar/perketat", headers=h, json={"aset_id": "rdp"})
    g = layanan(potret(klien, h)["kesiapan"], "listrik")
    assert g["rincian"]["temuan"] == 0 and g["kerawanan"] == 100


def test_insiden_belum_ditahan_membatasi_nilai_posko_paling_tinggi_d(klien):
    h = masuk(klien)
    klien.post("/api/simulasi", headers=h, json={"layanan_id": "kesehatan", "skenario": "ddos"})
    k = potret(klien, h)["kesiapan"]
    assert layanan(k, "kesehatan")["insiden"] == 30 and layanan(k, "kesehatan")["huruf"] == "E"
    assert k["nilai"] <= PLAFON_INSIDEN_AKTIF and k["huruf"] == "D" and k["batas"]
    JAM["t"] += 4
    klien.post("/api/soar/jalankan", headers=h, json={"layanan_id": "kesehatan", "aksi": "isolasi"})
    JAM["t"] += 1.3                                       # bukti → ≈1,2 dtk → pemutus selesai
    k = potret(klien, h)["kesiapan"]
    assert layanan(k, "kesehatan")["insiden"] == 60 and k["batas"] is None


# ---------- Triase: penutupan peringatan ----------
def test_false_positive_menurunkan_waspada_tanpa_menghapus_apa_pun(klien):
    h = masuk(klien)
    siarkan(klien, h, "CTI-109")
    halaman_awal = main.MENARA.rantai.buku.jumlah
    r = tutup(klien, h, "genset")
    assert r.status_code == 200
    j = r.json()
    assert j["status"] == "false_positive" and j["label"] == ISTILAH["tutup_fp"] and j["sumber"] == ["CTI-109"]
    k = potret(klien, h)
    assert "genset" not in prediksi(k)                    # tidak lagi dinaikkan ke WASPADA
    assert any(b["id"] == "CTI-109" for b in k["cti"]["berita"])   # berita CTI tetap aktif, tidak dihapus
    # halaman baru di Buku Rantai Bukti, rantai tetap utuh, dicerminkan ke log audit
    assert main.MENARA.rantai.buku.jumlah == halaman_awal + 1
    e = main.MENARA.rantai.daftar(1)[0]
    assert e["aksi"] == PERINGATAN_DITUTUP and e["detail"]["alasan"].startswith("Port Modbus") and e["aktor"] == "operator"
    assert main.MENARA.rantai.buku.verifikasi()["utuh"]
    assert any(x["aksi"] == PERINGATAN_DITUTUP and x["detail"]["status"] == "false_positive" for x in LOG.daftar(10))
    t = k["kesiapan"]["triase"]
    assert t["jumlah"] == {"selesai": 0, "false_positive": 1} and t["riwayat"][0]["aset"] == "genset"
    assert layanan(k["kesiapan"], "listrik")["insiden"] == 100


def test_selesai_dihitung_terpisah_dari_false_positive(klien):
    h = masuk(klien)
    siarkan(klien, h, "CTI-102")                          # RDP 3389 → WASPADA
    assert tutup(klien, h, "rdp", "selesai", "Akses RDP sudah ditutup manual oleh Perwira Siber Satuan").status_code == 200
    t = potret(klien, h)["kesiapan"]["triase"]
    assert t["jumlah"] == {"selesai": 1, "false_positive": 0} and t["riwayat"][0]["label"] == ISTILAH["tutup_selesai"]


def test_bukti_baru_membuka_peringatan_lagi(klien):
    h = masuk(klien)
    siarkan(klien, h, "CTI-109")
    tutup(klien, h, "genset")
    klien.post("/api/ai/latihan", headers=h, json={"aset_id": "genset"})   # sumber BARU: AI lokal
    p = prediksi(potret(klien, h))["genset"]
    assert p["proaktif"] and p["sumber"] == [SUMBER_AI]   # CTI-109 tetap tertutup, AI membuka lagi
    assert tutup(klien, h, "genset", alasan="Teknisi sedang mengalibrasi genset sesuai jadwal").status_code == 200
    assert "genset" not in prediksi(potret(klien, h))
    klien.post("/api/ai/latihan", headers=h, json={"aset_id": "genset"})   # latihan baru = episode baru
    assert prediksi(potret(klien, h))["genset"]["proaktif"]


def test_penutupan_berakhir_saat_berita_kedaluwarsa(klien):
    h = masuk(klien)
    siarkan(klien, h, "CTI-109")
    tutup(klien, h, "genset")
    JAM["t"] += 1000                                       # berita memudar dan habis
    potret(klien, h)
    assert "genset" not in main.MENARA._ditutup


@pytest.mark.parametrize("data,kode", [
    ({"aset_id": "genset", "status": "false_positive", "alasan": "ok"}, 422),            # alasan terlalu pendek
    ({"aset_id": "genset", "status": "abaikan", "alasan": "alasan yang cukup panjang"}, 422),
    ({"aset_id": "tidak-ada", "status": "selesai", "alasan": "alasan yang cukup panjang"}, 422),
    ({"aset_id": "genset", "status": "selesai", "alasan": "alasan yang cukup panjang", "lain": 1}, 422),
])
def test_masukan_aneh_ditolak(klien, data, kode):
    h = masuk(klien)
    siarkan(klien, h, "CTI-109")
    assert klien.post("/api/peringatan/tutup", headers=h, json=data).status_code == kode


def test_tidak_ada_peringatan_terbuka_ditolak_409(klien):
    h = masuk(klien)
    r = tutup(klien, h, "genset")
    assert r.status_code == 409 and "Tidak ada peringatan" in r.json()["detail"]


def test_aset_dalam_insiden_ditangani_lewat_playbook(klien):
    h = masuk(klien)
    siarkan(klien, h, "CTI-101")                          # SMB 445 → berbagi berkas WASPADA
    klien.post("/api/simulasi", headers=h, json={"layanan_id": "kesehatan", "skenario": "ransomware"})
    r = tutup(klien, h, "smb")
    assert r.status_code == 409 and "insiden aktif" in r.json()["detail"]


def test_hanya_operator_yang_boleh_menutup(klien):
    siarkan(klien, masuk(klien), "CTI-109")
    data = {"aset_id": "genset", "status": "false_positive", "alasan": "alasan yang cukup panjang"}
    assert klien.post("/api/peringatan/tutup", json=data).status_code == 401
    h = masuk(klien, "pengamat", "sandi-pengamat-uji-123")
    assert klien.post("/api/peringatan/tutup", headers=h, json=data).status_code == 403
