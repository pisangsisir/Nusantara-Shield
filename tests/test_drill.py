# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
Uji drill kesiapan (cyber drill untuk Operator non-ahli; Perpres 82/2022 Pasal 15: simulasi tanggap insiden).

Prinsip yang dikunci:
- Log cerita drill dinilai mesin deteksi yang SAMA dengan log asli (jalur impor). Tidak ada temuan yang disuntikkan.
- Kunci jawaban deteksi: aturan yang SEHARUSNYA menangkap cerita itu. Aturan yang diam ikut dilaporkan.
- Kunci jawaban pertanyaan tidak pernah dikirim ke browser sebelum pertanyaan dijawab; tiap pertanyaan sekali jawab.
- Nilai kesiapan berasal dari jejak yang sudah tercatat (MTTC, bukti, isolasi darurat), bukan dari klaim Operator.
  Rumusnya terbuka (app/drill.py) dan setiap komponen menyebut sumber angkanya.
- Hanya Operator yang memulai dan menjawab; Pengamat hanya melihat. Semua langkah drill masuk log audit berantai.
- Data sintetis saja: alamat dari blok dokumentasi RFC 5737, ditandai SIMULASI.
"""

import ipaddress
import re

import pytest
from fastapi.testclient import TestClient

from app import deteksi, drill, main
from app.audit import LOG
from app.istilah import ISTILAH
from app.keamanan import PEMBATAS

from test_ot_mitre_lapsit import teks_pdf

JAM = {"t": 20000.0}
KODE = "cadangan_dilepas"
OT = "genset_dari_kantor"


@pytest.fixture(autouse=True)
def bersihkan():
    PEMBATAS.reset()
    main.LAYANAN = main.salin_layanan_awal()
    JAM["t"] = 20000.0
    main.MENARA._jam = lambda: JAM["t"]
    main.MENARA.reset()
    main.MENARA.osint.berikut = 1e12
    main.DRILL.reset()
    yield
    main.DRILL.reset()                     # riwayat drill tidak boleh terbawa ke LAPSIT uji berkas lain


@pytest.fixture
def k():
    return TestClient(main.app)


def masuk(k, nama="operator", sandi="sandi-operator-uji-123"):
    j = k.post("/api/login", json={"nama": nama, "sandi": sandi}).json()
    return {"Authorization": f"Bearer {j['token']}"}


def mulai(k, h):
    r = k.post("/api/drill/mulai", headers=h, json={"kode": KODE})
    assert r.status_code == 200, r.text
    return r.json()


def kunci(no: int) -> str:
    """Kunci jawaban diambil dari state server (bukan dari API), seperti pengawas yang memegang lembar kunci."""
    return main.DRILL.aktif["pertanyaan"][no]["kunci"]


def jawab_semua_benar(k, h, n=4):
    for no in range(n):
        assert k.post("/api/drill/jawab", headers=h, json={"no": no, "pilihan": kunci(no)}).json()["benar"]


def selesai(k, h):
    r = k.post("/api/drill/selesai", headers=h)
    assert r.status_code == 200, r.text
    return r.json()


def audit(aksi):
    return [e for e in LOG.daftar(200) if e["aksi"] == aksi]


# ---------------------------------------------------------------- peran dan katalog
def test_pengamat_melihat_katalog_tetapi_tidak_bisa_memulai_atau_menjawab(k):
    hp = masuk(k, "pengamat", "sandi-pengamat-uji-123")
    j = k.get("/api/drill", headers=hp).json()
    assert [d["kode"] for d in j["katalog"]] == [KODE, OT] and j["aktif"] is None
    assert k.post("/api/drill/mulai", headers=hp, json={"kode": KODE}).status_code == 403
    mulai(k, masuk(k))
    assert k.post("/api/drill/jawab", headers=hp, json={"no": 0, "pilihan": "a"}).status_code == 403
    assert k.post("/api/drill/selesai", headers=hp).status_code == 403
    assert k.get("/api/drill", headers=hp).json()["aktif"]["kode"] == KODE      # tetap bisa memantau


def test_tanpa_login_ditolak(k):
    assert k.get("/api/drill").status_code == 401
    assert k.post("/api/drill/mulai", json={"kode": KODE}).status_code == 401


def test_kode_drill_dan_kolom_asing_ditolak(k):
    h = masuk(k)
    assert k.post("/api/drill/mulai", headers=h, json={"kode": "serang_balik"}).status_code == 422
    assert k.post("/api/drill/mulai", headers=h, json={"kode": KODE, "nilai": 100}).status_code == 422


# ---------------------------------------------------------------- log cerita = data sintetis lewat aturan yang sama
@pytest.mark.parametrize("kode", [KODE, OT])
def test_log_cerita_sintetis_hanya_memakai_alamat_dokumentasi(kode):
    teks = drill.log_cerita(kode, 1_800_000_000.0)
    assert "SIMULASI" in teks.splitlines()[0]
    for ip in set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", teks)):
        a = ipaddress.ip_address(ip)
        assert any(a in ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")), ip


def test_mulai_drill_memutar_log_cerita_lewat_mesin_deteksi_yang_sama(k):
    h = masuk(k)
    j = mulai(k, h)
    a = j["aktif"]
    assert a["kode"] == KODE and a["log"].startswith("# SIMULASI") and a["impor"]["dikenali"] >= 10
    # temuan lahir dari aturan saat log dibaca, berlabel log impor
    temuan = {t["aturan"]: t for t in main.MENARA._deteksi_tampil({})["temuan"]}
    assert {"login_gagal", "login_tembus"} <= set(temuan)
    # kunci jawaban deteksi: setiap aturan yang seharusnya menangkap cerita ini memang muncul
    assert a["deteksi"] == [{"aturan": "login_gagal", "nama": deteksi.ATURAN["login_gagal"]["nama"], "muncul": True},
                            {"aturan": "login_tembus", "nama": deteksi.ATURAN["login_tembus"]["nama"], "muncul": True}]
    # insiden latihan berjalan di layanan sasaran, lalu Operator merespons dari Action Center seperti biasa
    l = main.LAYANAN[a["layanan_id"]]
    assert l["insiden"] and l["insiden"]["skenario"] == "backup_dimatikan"
    assert audit("DRILL_MULAI")[0]["detail"] == {"drill": a["id"], "kode": KODE, "layanan": a["layanan_id"],
                                                  "temuan": 2}
    assert audit("IMPOR_LOG")                                     # jejak impor yang sama dengan log asli


def test_aturan_yang_diam_dilaporkan_di_kunci_jawaban(k, monkeypatch):
    """Detection drill: bila ambang aturan dinaikkan sampai cerita tidak tertangkap, drill harus mengatakannya."""
    monkeypatch.setitem(deteksi.ATURAN, "login_gagal", {**deteksi.ATURAN["login_gagal"], "ambang": 50})
    h = masuk(k)
    det = {d["aturan"]: d["muncul"] for d in mulai(k, h)["aktif"]["deteksi"]}
    assert det == {"login_gagal": False, "login_tembus": False}
    hasil = selesai(k, h)["hasil"]
    assert hasil["deteksi_lengkap"] is False and "tidak menangkap" in hasil["catatan_deteksi"]


def test_drill_kedua_ditolak_selama_masih_berjalan_dan_layanan_sibuk_ditolak(k):
    h = masuk(k)
    mulai(k, h)
    assert k.post("/api/drill/mulai", headers=h, json={"kode": KODE}).status_code == 409
    selesai(k, h)
    # layanan sasaran masih dalam insiden (belum dipulihkan): drill baru ditolak, tidak menimpa insiden
    assert k.post("/api/drill/mulai", headers=h, json={"kode": KODE}).status_code == 409


# ---------------------------------------------------------------- pertanyaan per fase IR
def test_kunci_jawaban_tidak_dikirim_sebelum_dijawab(k):
    h = masuk(k)
    a = mulai(k, h)["aktif"]
    assert [p["fase"] for p in a["pertanyaan"]] == ["Deteksi", "Analisis", "Penahanan", "Pemulihan"]
    for p in a["pertanyaan"]:
        assert "kunci" not in p and "penjelasan" not in p and len(p["opsi"]) == 4
    teks = str(k.get("/api/drill", headers=h).json())
    assert "'kunci'" not in teks and "penjelasan" not in teks


def test_pertanyaan_deteksi_menanyakan_jam_login_berhasil_di_log(k):
    h = masuk(k)
    a = mulai(k, h)["aktif"]
    baris = next(b for b in a["log"].splitlines() if "Accepted" in b)
    jam = re.search(r"T(\d\d:\d\d:\d\d)", baris)[1]
    p = a["pertanyaan"][0]
    assert jam in p["opsi"][kunci(0)] and len({*p["opsi"].values()}) == 4


def test_jawaban_dinilai_sekali_dan_penjelasan_dibuka_sesudahnya(k):
    h = masuk(k)
    mulai(k, h)
    salah = next(x for x in "abcd" if x != kunci(2))
    r = k.post("/api/drill/jawab", headers=h, json={"no": 2, "pilihan": salah}).json()
    assert r["benar"] is False and r["kunci"] == kunci(2) and len(r["penjelasan"]) > 40
    assert k.post("/api/drill/jawab", headers=h, json={"no": 2, "pilihan": kunci(2)}).status_code == 409
    p = k.get("/api/drill", headers=h).json()["aktif"]["pertanyaan"][2]
    assert p["dijawab"] == salah and p["kunci"] == kunci(2) and p["benar"] is False
    assert k.post("/api/drill/jawab", headers=h, json={"no": 9, "pilihan": "a"}).status_code == 422
    assert k.post("/api/drill/jawab", headers=h, json={"no": 0, "pilihan": "e"}).status_code == 422
    # log audit mencatat benar/salah, bukan isi pilihan
    assert audit("DRILL_JAWAB")[0]["detail"] == {"drill": main.DRILL.aktif["id"], "no": 3, "fase": "Penahanan",
                                                  "benar": False}


def test_jawab_tanpa_drill_aktif_ditolak(k):
    assert k.post("/api/drill/jawab", headers=masuk(k), json={"no": 0, "pilihan": "a"}).status_code == 409
    assert k.post("/api/drill/selesai", headers=masuk(k)).status_code == 409


# ---------------------------------------------------------------- nilai kesiapan dari jejak tercatat
def test_bukti_dulu_dan_cepat_memberi_nilai_penuh(k):
    h = masuk(k)
    a = mulai(k, h)["aktif"]
    jawab_semua_benar(k, h)
    JAM["t"] += 40
    assert k.post("/api/soar/jalankan", headers=h, json={"layanan_id": a["layanan_id"], "aksi": "isolasi"}).status_code == 200
    JAM["t"] += 1.3                                                 # pemutus pertama jatuh tempo (jeda 1,2 dtk)
    hasil = selesai(k, h)["hasil"]                                  # selesai memproses antrean SOAR lebih dulu
    assert hasil["nilai"] == 100 and hasil["huruf"] == "A"
    kom = {x["kunci"]: x for x in hasil["komponen"]}
    assert kom["ketepatan"]["nilai"] == 40 and kom["bukti"]["nilai"] == 30 and kom["kecepatan"]["nilai"] == 30
    assert kom["kecepatan"]["sumber"].startswith("MTTC") and "41" in kom["kecepatan"]["rincian"]
    assert kom["bukti"]["sumber"] == ISTILAH["buku_bukti"]
    assert hasil["deteksi_lengkap"] is True
    d = audit("DRILL_SELESAI")[0]["detail"]
    assert d["nilai"] == 100 and d["huruf"] == "A" and d["mttc_detik"] == 41 and d["darurat"] is False


def test_isolasi_darurat_tanpa_alasan_teknis_menurunkan_nilai_bukti(k):
    h = masuk(k)
    a = mulai(k, h)["aktif"]
    JAM["t"] += 30
    r = k.post("/api/soar/darurat", headers=h, json={"layanan_id": a["layanan_id"],
                                                    "alasan": "panik, putus dulu saja biar aman"})
    assert r.status_code == 200
    JAM["t"] += 2
    main.MENARA._proses_antre_soar(main.LAYANAN)
    kom = {x["kunci"]: x for x in selesai(k, h)["hasil"]["komponen"]}
    assert kom["bukti"]["nilai"] == 0 and "darurat" in kom["bukti"]["rincian"]
    assert kom["kecepatan"]["nilai"] == 30                          # memutus cepat tetap dihargai


def test_bukti_susulan_setelah_isolasi_darurat_mendapat_separuh(k):
    h = masuk(k)
    a = mulai(k, h)["aktif"]
    k.post("/api/soar/darurat", headers=h, json={"layanan_id": a["layanan_id"], "alasan": "agen forensik tidak merespons"})
    JAM["t"] += 2
    main.MENARA._proses_antre_soar(main.LAYANAN)
    assert k.post("/api/soar/jalankan", headers=h, json={"layanan_id": a["layanan_id"], "aksi": "amankan_bukti"}).status_code == 200
    kom = {x["kunci"]: x for x in selesai(k, h)["hasil"]["komponen"]}
    assert kom["bukti"]["nilai"] == 15 and "susulan" in kom["bukti"]["rincian"]


def test_tanpa_penahanan_nilai_bukti_dan_kecepatan_nol(k):
    h = masuk(k)
    mulai(k, h)
    hasil = selesai(k, h)["hasil"]
    kom = {x["kunci"]: x for x in hasil["komponen"]}
    assert kom["ketepatan"]["nilai"] == 0 and kom["bukti"]["nilai"] == 0 and kom["kecepatan"]["nilai"] == 0
    assert hasil["nilai"] == 0 and hasil["huruf"] == "E" and "belum ditahan" in kom["kecepatan"]["rincian"]


@pytest.mark.parametrize("detik,nilai", [(0, 30), (180, 30), (181, 20), (420, 20), (421, 10), (900, 10), (901, 0),
                                         (None, 0)])
def test_ambang_kecepatan_terbuka(detik, nilai):
    assert drill.nilai_kecepatan(detik) == nilai


def test_rumus_nilai_terbuka_dan_berjumlah_100():
    assert sum(b for _, b in drill.BOBOT.values()) == 100
    assert drill.BOBOT["ketepatan"][1] == 10 * 4 and drill.BOBOT["bukti"][1] == 30 and drill.BOBOT["kecepatan"][1] == 30


# ---------------------------------------------------------------- jejak: audit, LAPSIT, reset
def test_hasil_drill_tercetak_di_lapsit_sebagai_latihan(k):
    h = masuk(k)
    a = mulai(k, h)["aktif"]
    jawab_semua_benar(k, h)
    k.post("/api/soar/jalankan", headers=h, json={"layanan_id": a["layanan_id"], "aksi": "isolasi"})
    JAM["t"] += 5
    selesai(k, h)
    teks = teks_pdf(k.post("/api/lapsit", headers=h).content)
    for kata in (ISTILAH["drill"].upper(), "LATIHAN", "Perpres 82/2022", "Ketepatan keputusan", "Bukti sebelum putus",
                 "Kecepatan penahanan", "100/100", "operator"):
        assert kata in teks, kata


def test_lapsit_rutin_tanpa_drill_tidak_berubah(k):
    teks = teks_pdf(k.post("/api/lapsit", headers=masuk(k)).content)
    assert ISTILAH["drill"].upper() not in teks and "Halaman 1 dari 1" in teks


def test_reset_demo_membatalkan_drill_aktif_tetapi_riwayat_tetap(k):
    h = masuk(k)
    mulai(k, h)
    selesai(k, h)
    k.post("/api/reset-demo", headers=h)
    mulai(k, h)
    k.post("/api/reset-demo", headers=h)
    j = k.get("/api/drill", headers=h).json()
    assert j["aktif"] is None and len(j["riwayat"]) == 1
    assert audit("DRILL_DIBATALKAN")[0]["detail"]["alasan"] == "reset demo"


def test_riwayat_menampilkan_hasil_terbaru_lebih_dulu(k):
    h = masuk(k)
    for _ in range(2):
        a = mulai(k, h)["aktif"]
        selesai(k, h)
        main.LAYANAN[a["layanan_id"]]["insiden"] = None             # layanan dibebaskan untuk drill berikutnya
        main.MENARA.insiden_ditutup(a["layanan_id"])
    r = k.get("/api/drill", headers=h).json()["riwayat"]
    assert len(r) == 2 and r[0]["id"] != r[1]["id"] and r[0]["selesai"] >= r[1]["selesai"]


# ---------------------------------------------------------------- skenario OT: keluaran Suricata eve.json
def mulai_ot(k, h):
    r = k.post("/api/drill/mulai", headers=h, json={"kode": OT})
    assert r.status_code == 200, r.text
    return r.json()["aktif"]


def test_drill_ot_membaca_eve_json_lewat_aturan_ot_yang_sama(k):
    h = masuk(k)
    a = mulai_ot(k, h)
    assert a["format"] == "Suricata eve.json" and a["impor"]["format"] == "Suricata eve.json"
    assert all(d["muncul"] for d in a["deteksi"])
    assert [d["aturan"] for d in a["deteksi"]] == ["ot_tanpa_izin", "tulis_ot_luar_jadwal", "rantai_it_ot"]
    ins = main.LAYANAN["listrik"]["insiden"]
    assert ins and ins["skenario"] == "sabotase_ot"
    temuan = main.MENARA._deteksi_tampil({})["temuan"]
    assert all(t["sumber"] == drill.PENYUSUP_OT for t in temuan)          # HMI resmi membaca: bukan temuan


@pytest.mark.parametrize("sekarang_jam", [9, 15, 23, 1])
def test_cerita_ot_selalu_di_luar_jendela_pemeliharaan(sekarang_jam):
    """Perintah tulis wajar pukul 22.00–02.00. Cerita OT ditaruh pada pukul 14.00 terakhir agar tetap tertangkap,
    kapan pun drill dibuka."""
    from datetime import datetime
    from app.lapsit import zona
    kini = datetime(2026, 11, 9, sekarang_jam, 30, tzinfo=zona()[1]).timestamp()
    awal = drill.awal_cerita(OT, kini)
    d = datetime.fromtimestamp(awal, zona()[1])
    assert (d.hour, d.minute) == (14, 0) and awal < kini
    assert drill.awal_cerita(KODE, kini) == kini - 240


def test_drill_ot_bukti_dulu_memberi_nilai_penuh(k):
    h = masuk(k)
    a = mulai_ot(k, h)
    jawab_semua_benar(k, h)
    JAM["t"] += 20
    assert k.post("/api/soar/jalankan", headers=h, json={"layanan_id": a["layanan_id"], "aksi": "isolasi"}).status_code == 200
    JAM["t"] += 1.3
    hasil = selesai(k, h)["hasil"]
    assert hasil["nilai"] == 100 and hasil["mttc_detik"] == 21 and hasil["deteksi_lengkap"]


def test_kunci_jawaban_ot_tidak_bocor_dan_genset_tidak_dimatikan_adalah_jawabannya(k):
    h = masuk(k)
    a = mulai_ot(k, h)
    assert all("kunci" not in p for p in a["pertanyaan"])
    tahan = main.DRILL.aktif["pertanyaan"][2]
    assert "Genset tetap menyala" in tahan["opsi"][tahan["kunci"]]
    assert "Matikan genset" in tahan["opsi"]["a"] and tahan["kunci"] != "a"
