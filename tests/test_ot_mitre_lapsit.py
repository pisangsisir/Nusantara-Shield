"""
Uji Fase 2: aturan OT deterministik, label MITRE ATT&CK, label batasan sumber data, dan pengesahan LAPSIT.

Prinsip yang dikunci:
- Aturan OT lahir dari peristiwa mentah dengan aturan terbuka: jalur OT yang tidak terdaftar, perintah TULIS
  Modbus di luar jendela pemeliharaan 22.00–02.00, dan rantai keduanya dari sumber yang sama.
  Membaca register, jalur resmi, atau menulis di dalam jendela: BUKAN temuan.
- Dua kunci tetap utuh: temuan OT hanya menaikkan pengendali genset ke WASPADA. Tidak ada insiden, isolasi,
  bukti, atau antrean SOAR yang terpicu; memutus tetap keputusan Operator.
- Setiap aturan deteksi dan skenario latihan punya label teknik MITRE ATT&CK; AI sengaja tidak diberi label.
- Setiap peringatan menulis sumber datanya (label batasan) secara jujur.
- LAPSIT PDF memuat teknik ATT&CK, label sumber data, dan blok pengesahan dua tanda tangan.
"""

import base64
import re
import zlib

import pytest
from fastapi.testclient import TestClient

from app import lapsit, main
from app.data_contoh import SKENARIO
from app.deteksi import (ATURAN, FUNGSI_TULIS_MODBUS, IP_PENYUSUP, IP_REKAYASA_OT, JALUR_OT_DIIZINKAN,
                         JENDELA_PEMELIHARAAN, MesinDeteksi, dalam_jendela_pemeliharaan)
from app.istilah import ISTILAH, nama_manajemen
from app.keamanan import PEMBATAS
from app.mitre import PEMETAAN, TEKNIK, teknik

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


def latih(k, h, jenis, maju=15):
    r = k.post("/api/deteksi/latihan", headers=h, json={"jenis": jenis})
    assert r.status_code == 200, r.text
    JAM["t"] += maju
    return r.json()


def konek_ot(m, t, sumber=IP_PENYUSUP, aset="genset"):
    return m.proses({"jenis": "koneksi_ot", "sumber": sumber, "aset": aset}, t)


def modbus(m, t, jam=14, fungsi=16, sumber=IP_PENYUSUP, aset="genset"):
    return m.proses({"jenis": "modbus", "sumber": sumber, "aset": aset, "fungsi": fungsi, "jam": jam}, t)


def teks_pdf(pdf: bytes) -> str:
    """Teks yang tercetak di PDF: aliran ASCII85+Flate dibuka, lalu semua string (…) Tj digabung dengan spasi
    agar frasa yang terpotong ganti baris tetap bisa dicari."""
    hasil = []
    for aliran in re.findall(rb"stream\r?\n(.*?)endstream", pdf, re.S):
        data = aliran.strip()
        if data.endswith(b"~>"):                         # ReportLab: ASCII85 di atas Flate
            data = base64.a85decode(data[:-2])
        try:
            isi = zlib.decompress(data).decode("latin-1")
        except zlib.error:
            continue
        hasil += [re.sub(r"\\([()\\])", r"\1", s) for s in re.findall(r"\(((?:\\.|[^\\)])*)\) Tj", isi)]
    return re.sub(r" {2,}", " ", " ".join(hasil))      # v5.4.3: istilah asing dicetak miring = potongan teks sendiri


# ---------------------------------------------------------------- aturan OT (unit, tanpa server)
def test_aturan_ot_terbuka_sesuai_dokumentasi():
    """Angka ini tertulis di Dokumentasi Teknis §2.8; mengubahnya wajib mengubah dokumen juga."""
    assert JENDELA_PEMELIHARAAN == (22, 2) and JALUR_OT_DIIZINKAN == {"192.0.2.140"}
    assert FUNGSI_TULIS_MODBUS == {5, 6, 15, 16}
    assert {a: (ATURAN[a]["keparahan"], ATURAN[a]["peluang"]) for a in ("ot_tanpa_izin", "tulis_ot_luar_jadwal", "rantai_it_ot")} \
        == {"ot_tanpa_izin": ("tinggi", 0.50), "tulis_ot_luar_jadwal": ("kritis", 0.70), "rantai_it_ot": ("kritis", 0.90)}


def test_jalur_ot_resmi_bukan_temuan():
    m = MesinDeteksi()
    assert konek_ot(m, 1.0, sumber=IP_REKAYASA_OT) == []
    assert m.temuan == []


def test_koneksi_ot_tanpa_izin_menjadi_temuan_sekali_per_episode():
    m = MesinDeteksi()
    baru = konek_ot(m, 1.0)
    assert len(baru) == 1 and baru[0].aturan == "ot_tanpa_izin" and baru[0].keparahan == "tinggi"
    assert konek_ot(m, 2.0) == [] and m.temuan[0].jumlah == 2      # episode yang sama diperpanjang
    assert "tidak ada di daftar jalur OT yang diizinkan" in m.temuan[0].alasan()


def test_membaca_register_bukan_temuan_walau_siang_hari():
    m = MesinDeteksi()
    assert all(modbus(m, i, fungsi=f) == [] for i, f in enumerate((1, 2, 3, 4)))


@pytest.mark.parametrize("jam,temuan", [(22, False), (23, False), (0, False), (1, False),
                                        (2, True), (8, True), (14, True), (21, True)])
def test_jendela_pemeliharaan_22_sampai_02(jam, temuan):
    assert dalam_jendela_pemeliharaan(jam) is not temuan
    m = MesinDeteksi()
    assert bool(modbus(m, 1.0, jam=jam, sumber=IP_REKAYASA_OT)) is temuan


def test_jalur_resmi_menulis_di_luar_jadwal_tetap_temuan_tanpa_rantai():
    m = MesinDeteksi()
    konek_ot(m, 1.0, sumber=IP_REKAYASA_OT)
    baru = modbus(m, 2.0, sumber=IP_REKAYASA_OT)
    assert [t.aturan for t in baru] == ["tulis_ot_luar_jadwal"] and baru[0].keparahan == "kritis"
    assert "pukul 14.00; jendela pemeliharaan 22.00–02.00" in baru[0].alasan()


def test_koneksi_tanpa_izin_disusul_tulis_menjadi_rantai_kritis():
    m = MesinDeteksi()
    k1 = konek_ot(m, 1.0)[0]
    baru = modbus(m, 4.0)
    assert [t.aturan for t in baru] == ["tulis_ot_luar_jadwal", "rantai_it_ot"]
    rantai = baru[1]
    assert rantai.keparahan == "kritis" and rantai.rincian["koneksi"] == k1.id
    assert modbus(m, 5.0) == [] and modbus(m, 6.0) == []           # serangan berlanjut: tidak menggandakan temuan


def test_rantai_tidak_terbentuk_bila_koneksi_sudah_lama():
    m = MesinDeteksi()
    konek_ot(m, 1.0)
    baru = modbus(m, 1.0 + ATURAN["rantai_it_ot"]["jendela"] + 1)
    assert [t.aturan for t in baru] == ["tulis_ot_luar_jadwal"]


# ---------------------------------------------------------------- terpadu: dua kunci tetap utuh
def test_latihan_akses_ot_menaikkan_genset_ke_waspada_tanpa_memutus(k):
    h = masuk(k)
    r = latih(k, h, "akses_ot")
    assert r["aset_id"] == "genset" and r["peristiwa"] == 6
    p = potret(k, h)
    g = {x["id"]: x for x in p["cti"]["prediksi"]}["genset"]
    assert g["proaktif"] and g["persen"] >= 95
    assert {d["keparahan"] for d in g["deteksi"]} == {"tinggi", "kritis"}
    genset = {s["id"]: s for s in p["topologi"]["simpul"]}["genset"]
    assert genset["status"] == "waspada"                             # Kunci 1: hanya WASPADA
    # Kunci 2: tidak ada insiden, isolasi, bukti, atau antrean SOAR
    assert not any(l["insiden"] for l in main.LAYANAN.values())
    assert main.MENARA._antre_soar == [] and main.MENARA._bukti == {}
    aturan = {x["aturan"] for x in p["peringatan"] if x["jenis"] == "deteksi"}
    assert aturan == {"ot_tanpa_izin", "tulis_ot_luar_jadwal", "rantai_it_ot"}


def test_latihan_akses_ot_hanya_untuk_genset_dan_operator(k):
    h = masuk(k)
    assert k.post("/api/deteksi/latihan", headers=h, json={"jenis": "akses_ot", "aset_id": "ssh"}).status_code == 422
    hp = masuk(k, "pengamat", "sandi-pengamat-uji-123")
    assert k.post("/api/deteksi/latihan", headers=hp, json={"jenis": "akses_ot"}).status_code == 403


# ---------------------------------------------------------------- MITRE ATT&CK
def test_setiap_aturan_dan_skenario_punya_label_attck():
    assert set(ATURAN) | set(SKENARIO) <= set(PEMETAAN)
    for t in {x for v in PEMETAAN.values() for x in v}:
        nama, matriks = TEKNIK[t]
        assert re.fullmatch(r"T\d{4}", t) and nama
        assert (matriks == "ICS") == t.startswith("T08")             # ATT&CK for ICS memakai T08xx
    assert [x["id"] for x in teknik("tulis_ot_luar_jadwal")] == ["T0855"] and teknik("tidak-ada") == []


def test_peringatan_dan_log_membawa_label_attck(k):
    h = masuk(k)
    latih(k, h, "login_gagal", maju=30)
    p = potret(k, h)
    det = [x for x in p["peringatan"] if x["jenis"] == "deteksi"][0]
    assert [m["id"] for m in det["mitre"]] == ["T1110"]
    assert any("[ATT&CK T1110 Brute Force]" in e["pesan"] for e in p["peristiwa"])
    assert [m["id"] for m in p["deteksi"]["temuan"][0]["mitre"]] == ["T1110"]
    assert k.post("/api/simulasi", headers=h, json={"layanan_id": "kesehatan", "skenario": "ransomware"}).status_code == 200
    ins = [x for x in potret(k, h)["peringatan"] if x["jenis"] == "insiden"][0]
    assert [m["id"] for m in ins["mitre"]] == ["T1486"]


def test_ai_sengaja_tidak_diberi_label_attck(k):
    h = masuk(k)
    assert k.post("/api/ai/latihan", headers=h, json={"aset_id": "genset"}).status_code == 200
    JAM["t"] += 2
    ai = [x for x in potret(k, h)["peringatan"] if x["jenis"] == "ai"]
    assert ai and ai[0]["mitre"] == []


# ---------------------------------------------------------------- label batasan (kejujuran)
def test_setiap_peringatan_menulis_sumber_datanya(k):
    h = masuk(k)
    latih(k, h, "akses_ot")
    assert k.post("/api/ai/latihan", headers=h, json={"aset_id": "ssh"}).status_code == 200
    assert k.post("/api/simulasi", headers=h, json={"layanan_id": "imigrasi", "skenario": "ddos"}).status_code == 200
    JAM["t"] += 2
    daftar = potret(k, h)["peringatan"]
    assert {x["jenis"] for x in daftar} >= {"deteksi", "ai", "insiden"}
    for x in daftar:
        assert x["sumber_data"].startswith("Sumber: ")
    sumber = {x["jenis"]: x["sumber_data"] for x in daftar}
    assert "sintetis" in sumber["deteksi"] and "sintetis" in sumber["ai"] and "simulasi" in sumber["insiden"]


# ---------------------------------------------------------------- LAPSIT PDF
def test_lapsit_memuat_attck_sumber_data_dan_dua_tanda_tangan(k):
    h = masuk(k)
    latih(k, h, "akses_ot")
    assert k.post("/api/simulasi", headers=h, json={"layanan_id": "listrik", "skenario": "sabotase_ot"}).status_code == 200
    JAM["t"] += 3
    assert k.post("/api/soar/jalankan", headers=h, json={"layanan_id": "listrik", "aksi": "isolasi"}).status_code == 200
    JAM["t"] += 10                                                  # antrean pemutus SOAR jatuh tempo
    r = k.post("/api/lapsit", headers=h)
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    teks = teks_pdf(r.content)
    for kata in ("T0886", "T0855", "Unauthorized Command Message", "Peringatan Terbaru", "peristiwa latihan sintetis",
                 ISTILAH["ttd_judul"], ISTILAH["ttd_pembuat"], ISTILAH["ttd_mengetahui"], *nama_manajemen(),
                 "NUSANTARA SHIELD", ISTILAH["laporan"].upper(), "Laporan insiden (1 aktif)", "LAPSIT/NS/",
                 # LAPSIT formal: ringkasan naratif, dampak, IoC, tindakan bercap waktu dan beraktor, cara verifikasi
                 "Ringkasan Eksekutif", "terjadi insiden", "Dampak operasional", "genset TIDAK dimatikan",
                 "Indikator Kompromi (IoC)", "203.0.113.45:502", "Diblokir di firewall (simulasi)",
                 "Write Multiple Registers", "Waktu penahanan (MTTC)", "otomatis melalui SOAR", "WIB",
                 "Cara memverifikasi", "HMAC-SHA256", ISTILAH["buku_bukti"], "tools/verifikasi_audit.py --cocokkan"):
        assert kata in teks, kata
    assert re.search(r"T\+\d+ dtk", teks) and "BB-2026-" in teks              # tindakan bercap T+ dan nomor bukti
    assert re.search(r"Halaman 1 dari \d", teks)                   # kop dan kaki di setiap halaman
    # v5.4.3 · PUEBI: pukul dipisah titik, tanggal di kalimat memakai nama bulan, judul bagian berhuruf kapital,
    # kata baku (prosedur darurat, antartindakan, melalui), garis miring tanpa spasi
    assert re.search(r"\d{1,2} [A-Z][a-z]+ \d{4} pukul \d{2}\.\d{2}\.\d{2} WIB", teks)
    assert re.search(r"\d{2}-\d{2}-\d{4} \d{2}\.\d{2}\.\d{2} WIB", teks)
    assert not re.search(r"\d{2}:\d{2}(:\d{2})? WIB", teks)
    for kata in ("Status Layanan dan Dampak Operasional", "Insiden Aktif dan Tindakan", "Integritas Log Audit",
                 "Prosedur darurat", "antartindakan", "Kasi Siber/Dansat", "Aset/konteks"):
        assert kata in teks, kata
    assert "Dibuat oleh: Operator (akun operator" in teks and "disegel oleh akun operator" in teks
    for salah in ("ontinjensi", "antar-tindakan", " lewat ", " tak biasa", " / "):
        assert salah not in teks, salah


def test_lapsit_tanpa_peringatan_tetap_berpengesahan(k, monkeypatch, tmp_path):
    r = k.post("/api/lapsit", headers=masuk(k, "pengamat", "sandi-pengamat-uji-123"))
    teks = teks_pdf(r.content)
    assert r.status_code == 200 and "Tidak ada peringatan." in teks and ISTILAH["ttd_pembuat"] in teks
    # v5.4.3: bagian Tindak lanjut membuat laporan rutin dua halaman; pengesahan tetap utuh dalam satu halaman
    assert "Laporan rutin" in teks and "Halaman 2 dari 2" in teks and "Halaman 1 dari 3" not in teks
    assert "Dibuat oleh: Pengamat (akun pengamat" in teks           # peran berhuruf kapital, nama akun apa adanya
    assert "Pemeriksaan rutin" in teks and "Tidak ada insiden aktif." in teks and "Tidak ada indikator kompromi" in teks
    # logo kop digambar sebagai vektor dari static/logo.svg; bila berkasnya hilang, LAPSIT tetap terbit tanpa logo
    from reportlab.pdfgen.canvas import Canvas
    assert lapsit.gambar_logo(Canvas(str(tmp_path / "a.pdf")), 0, 0, 50)
    monkeypatch.setattr(lapsit, "LOGO_SVG", tmp_path / "tidak-ada.svg")
    assert not lapsit.gambar_logo(Canvas(str(tmp_path / "b.pdf")), 0, 0, 50)
    assert k.post("/api/lapsit", headers=masuk(k)).content.startswith(b"%PDF")
