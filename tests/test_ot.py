"""
Uji Fase 6 — sinergi IT/OT: aset teknologi operasional (pengendali genset, Modbus/TCP port 502).

Prinsip yang dikunci:
- Aset OT terdaftar di inventaris yang sama dengan aset IT: tampil di topologi (zona kendali),
  di radar (zona internal), dan bisa dibuka ke profil layanan Genset & Catu Daya RS Kesdam.
- Kabar ancaman protokol industri Modbus di Radio CTI MENAIKKAN genset ke WASPADA sebelum serangan
  (0,80 keyakinan × 0,75 paparan × 1,1 bonus sektor energi ≈ 66 %).
- Tombol Perketat menurunkan peluang genset di bawah ambang, sama seperti aset IT.
- Kabar OT tidak menyentuh aset IT, dan kabar IT tidak menyentuh aset OT (tidak ada alarm palsu).
- Skenario SABOTASE OT: bukti dulu, lalu ≈1,2 detik kemudian JALUR kantor → zona kendali diputus
  (NIST SP 800-82); genset tidak dimatikan, beralih ke kendali lokal. Pemulihan jalur kendali
  terkunci sampai sidik jari SHA-256 bukti cocok ulang.
"""

import pytest
from fastapi.testclient import TestClient

from app import main
from app.audit import LogAudit
from app.bukti import RantaiBukti
from app.keamanan import PEMBATAS
from app.penomoran import PencacahIR

JAM = {"t": 5000.0}


@pytest.fixture(autouse=True)
def bersihkan():
    PEMBATAS.reset()
    main.LAYANAN = main.salin_layanan_awal()
    JAM["t"] = 5000.0
    main.MENARA._jam = lambda: JAM["t"]
    main.MENARA.reset()
    main.MENARA.osint.berikut = 1e12        # matikan siaran otomatis: uji yang menentukan berita
    asli = main.MENARA.rantai
    main.MENARA.rantai = RantaiBukti(LogAudit("NS_BUKTI_FILE_UJI", "-", "buku uji"), PencacahIR(None))
    yield
    main.MENARA.rantai = asli


@pytest.fixture
def klien():
    return TestClient(main.app)


@pytest.fixture
def h(klien):
    j = klien.post("/api/login", json={"nama": "operator", "sandi": "sandi-operator-uji-123"}).json()
    return {"Authorization": f"Bearer {j['token']}"}


def potret(klien, h):
    return klien.get("/api/telemetri", headers=h).json()


def simpul(k):
    return {s["id"]: s for s in k["topologi"]["simpul"]}


def siarkan(klien, h, berita_id):
    r = klien.post("/api/cti/siarkan", headers=h, json={"berita_id": berita_id})
    main.MENARA.osint.berikut = 1e12
    return r


def test_genset_terdaftar_sebagai_aset_ot_di_topologi_dan_radar(klien, h):
    k = potret(klien, h)
    g = simpul(k)["genset"]
    assert (g["ip"], g["port"], g["status"]) == ("192.0.2.120", 502, "normal")
    assert g["layanan"] == "listrik"                           # klik → profil Genset RS Kesdam
    kabel = {(c["dari"], c["ke"]) for c in k["topologi"]["kabel"]}
    assert ("core", "genset") in kabel
    titik = {t["ip"]: t for t in k["radar"]["titik"]}
    assert titik["192.0.2.120"]["zona"] == "internal" and titik["192.0.2.120"]["port"] == 502


def test_kabar_modbus_menaikkan_genset_ke_waspada_sebelum_serangan(klien, h):
    r = siarkan(klien, h, "CTI-109")
    assert r.status_code == 200
    assert [c["id"] for c in r.json()["korelasi"]] == ["genset"]
    k = potret(klien, h)
    g = simpul(k)["genset"]
    assert g["status"] == "waspada" and "Waspada proaktif" in g["catatan"]
    assert 60 <= g["prob"] <= 70                               # 0,80 × 0,75 × 1,1 ≈ 66 %
    assert k["cti"]["prediksi"][0]["id"] == "genset"
    assert not any(l["insiden"] for l in k["layanan"])         # peringatan dini: belum ada serangan
    assert {s["id"]: s for s in k["peta"]["serangan"]}["cti-CTI-109"]["status"] == "waspada"


def test_perketat_genset_menurunkan_peluang_di_bawah_ambang(klien, h):
    siarkan(klien, h, "CTI-109")
    assert klien.post("/api/soar/perketat", headers=h, json={"aset_id": "genset"}).status_code == 200
    g = simpul(potret(klien, h))["genset"]
    assert g["status"] == "normal" and g["prob"] < 30          # paparan dipotong 70 %
    assert klien.post("/api/soar/perketat", headers=h, json={"aset_id": "genset"}).status_code == 409


def test_kabar_ot_dan_kabar_it_tidak_saling_memicu_alarm_palsu(klien, h):
    siarkan(klien, h, "CTI-109")                               # Modbus → hanya OT
    s = simpul(potret(klien, h))
    assert [i for i, v in s.items() if v["status"] == "waspada" and v["prob"]] == ["genset"]
    main.MENARA.reset()
    main.MENARA.osint.berikut = 1e12
    siarkan(klien, h, "CTI-103")                               # API web port 8080 → hanya IT
    s = simpul(potret(klien, h))
    assert s["genset"]["prob"] is None and s["genset"]["status"] == "normal"
    assert s["api"]["status"] == "waspada"


# ---------- Fase 6: isolasi OT sungguhan (skenario sabotase_ot) ----------
def _picu_sabotase(klien, h):
    r = klien.post("/api/simulasi", headers=h, json={"layanan_id": "listrik", "skenario": "sabotase_ot"})
    assert r.status_code == 200


def _kabel(k):
    return {(c["dari"], c["ke"]): c["status"] for c in k["topologi"]["kabel"]}


def test_sabotase_ot_bukti_dulu_lalu_jalur_it_ot_diputus_genset_tetap_menyala(klien, h):
    _picu_sabotase(klien, h)
    awal = potret(klien, h)
    assert simpul(awal)["genset"]["status"] == "kritis"
    r = klien.post("/api/soar/jalankan", headers=h, json={"layanan_id": "listrik", "aksi": "isolasi"})
    assert r.status_code == 200 and r.json()["dijadwalkan"][:2] == ["amankan_bukti", "putus_jalur_ot"]
    k = potret(klien, h)
    assert simpul(k)["genset"]["status"] == "kritis" and _kabel(k)[("core", "genset")] != "putus"  # bukti dulu
    assert main.MENARA._bukti["listrik"]["nomor"].startswith("BB-")
    JAM["t"] += 1.3                                                    # ≈ 1,2 detik setelah bukti aman
    k = potret(klien, h)
    g = simpul(k)["genset"]
    assert g["status"] == "isolasi" and "kendali lokal" in g["catatan"]  # jalur diputus, genset TIDAK dimatikan
    assert _kabel(k)[("core", "genset")] == "putus"
    assert any("Webhook (simulasi) ke sakelar terkelola zona kendali" in p["pesan"]
               for p in k["peristiwa"] if p["layanan"] == "listrik")              # pemicu sakelar tercatat
    JAM["t"] += 1.3
    k = potret(klien, h)
    ins = next(l for l in k["layanan"] if l["id"] == "listrik")["insiden"]
    assert ins["langkah_selesai"][:3] == [True, True, True]             # bukti → putus jalur → cabut akses
    assert k["komando"]["listrik"]["ir"]["keparahan"] == "SEV-1"         # LAPSIT terbit setelah semua pemutus


def test_sabotase_ot_pemulihan_jalur_kendali_terkunci_sampai_hash_cocok(klien, h):
    _picu_sabotase(klien, h)
    klien.post("/api/soar/jalankan", headers=h, json={"layanan_id": "listrik", "aksi": "isolasi"})
    JAM["t"] += 2.6
    assert klien.post("/api/playbook/langkah", headers=h,
                      json={"layanan_id": "listrik", "indeks": 4, "selesai": True}).status_code == 200  # cek fisik
    nomor = main.MENARA._bukti["listrik"]["nomor"]
    main.MENARA.rantai._uji_rusak_brankas(nomor, "konfigurasi_pengendali_genset.bin")
    r = klien.post("/api/soar/jalankan", headers=h, json={"layanan_id": "listrik", "aksi": "pulihkan"})
    assert r.status_code == 409 and "TIDAK COCOK" in r.json()["detail"]
    assert simpul(potret(klien, h))["genset"]["status"] == "isolasi"     # jalur tetap terputus
