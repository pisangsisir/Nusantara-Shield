"""
Uji telemetri & siaran langsung — memastikan "dapur" memasak dengan benar
dan "pelayan" hanya mengantar ke tamu yang sah.
Jalankan:  pytest -q
"""

import asyncio
import re
import time

import pytest
from fastapi.testclient import TestClient

from app import main
from app.keamanan import KONFIG, PEMBATAS, SIARAN, cabut_token

JAM = {"t": 1000.0}  # jam palsu: uji bisa "memajukan waktu" tanpa menunggu


@pytest.fixture(autouse=True)
def bersihkan():
    PEMBATAS.reset()
    main.LAYANAN = main.salin_layanan_awal()
    JAM["t"] = 1000.0
    main.MENARA._jam = lambda: JAM["t"]
    main.MENARA.reset()
    umur = KONFIG.umur_siaran_detik
    yield
    KONFIG.umur_siaran_detik = umur


@pytest.fixture
def klien():
    return TestClient(main.app)


def masuk(klien, nama="operator", sandi="sandi-operator-uji-123"):
    j = klien.post("/api/login", json={"nama": nama, "sandi": sandi}).json()
    return j["token"], {"Authorization": f"Bearer {j['token']}"}


def potret(klien, h):
    r = klien.get("/api/telemetri", headers=h)
    assert r.status_code == 200
    return r.json()


def majukan(detik):
    JAM["t"] += detik


# ---------- akses ----------
@pytest.mark.parametrize("jalur", ["/api/telemetri", "/api/telemetri/siaran"])
def test_telemetri_wajib_login(klien, jalur):
    assert klien.get(jalur).status_code == 401


def test_pengamat_boleh_melihat_tetapi_tidak_memicu(klien):
    _, h = masuk(klien, "pengamat", "sandi-pengamat-uji-123")
    assert potret(klien, h)["peran"] == "pengamat"
    r = klien.post("/api/simulasi", headers=h, json={"layanan_id": "pajak", "skenario": "ddos"})
    assert r.status_code == 403


# ---------- isi potret ----------
def test_potret_awal(klien):
    _, h = masuk(klien)
    k = potret(klien, h)
    assert k["postur"]["tingkat"] == "waspada"          # 2 layanan kuning + port RDP terbuka
    assert k["kpi"]["layanan_sehat"] == 4 and k["kpi"]["host_terpantau"] == 9   # 8 IT + 1 OT (Fase 6)
    assert not any(s["id"] == "ancaman" for s in k["topologi"]["simpul"])
    assert len(k["radar"]["titik"]) == 9 and k["radar"]["putaran_ms"] == 3200   # + genset (OT)
    assert k["lalu_lintas"]["ambang"] == {"waspada": 60, "kritis": 85}
    assert all(0 <= t["sudut"] <= 6.2832 for t in k["radar"]["titik"])


def test_ddos_menggerakkan_semua_panel(klien):
    _, h = masuk(klien)
    versi_awal = potret(klien, h)["versi"]
    klien.post("/api/simulasi", headers=h, json={"layanan_id": "kesehatan", "skenario": "ddos"})
    majukan(30)
    k = potret(klien, h)
    assert k["versi"] > versi_awal
    assert k["lalu_lintas"]["beban"] >= 85 and k["lalu_lintas"]["zona"] == "kritis"
    assert k["postur"]["tingkat"] == "kritis" and k["radar"]["putaran_ms"] == 2200
    ips = {t["ip"]: t for t in k["radar"]["titik"]}
    assert ips["198.51.100.23"]["status"] == "kritis"
    assert sum(1 for t in k["radar"]["titik"] if t["nama"] == "Sumber trafik banjir") == 16
    simpul = {s["id"]: s["status"] for s in k["topologi"]["simpul"]}
    assert simpul["fw"] == "kritis" and simpul["ancaman"] == "kritis"
    # kronologi gejala diteteskan bertahap, lengkap dengan jarak waktu T-…
    rel = [p["rel_menit"] for p in k["peristiwa"] if p["layanan"] == "kesehatan" and p["rel_menit"] is not None]
    assert rel == [-10, -5, 0]


def test_peristiwa_diteteskan_bertahap(klien):
    _, h = masuk(klien)
    klien.post("/api/simulasi", headers=h, json={"layanan_id": "imigrasi", "skenario": "ransomware"})
    hitung = lambda: sum(1 for p in potret(klien, h)["peristiwa"] if p["rel_menit"] is not None)
    assert hitung() == 0
    majukan(1.5)
    assert hitung() == 2
    majukan(10)
    assert hitung() == 5


def test_langkah_playbook_mengubah_peta_dan_radar(klien):
    _, h = masuk(klien)
    klien.post("/api/simulasi", headers=h, json={"layanan_id": "imigrasi", "skenario": "ransomware"})
    k = potret(klien, h)
    simpul = {s["id"]: s["status"] for s in k["topologi"]["simpul"]}
    assert simpul["smb"] == "kritis" and simpul["ancaman"] == "kritis"

    for i in (0, 1):     # Fase 4: langkah 1 = amankan bukti, langkah 2 = isolasi
        klien.post("/api/playbook/langkah", headers=h, json={"layanan_id": "imigrasi", "indeks": i, "selesai": True})
    k = potret(klien, h)
    simpul = {s["id"]: s["status"] for s in k["topologi"]["simpul"]}
    kabel = {(c["dari"], c["ke"]): c["status"] for c in k["topologi"]["kabel"]}
    assert simpul["smb"] == "isolasi" and simpul["ancaman"] == "isolasi"
    assert kabel[("core", "smb")] == "putus" and kabel[("ancaman", "internet")] == "putus"
    assert k["efek_langkah"]["ransomware"][1]

    for i in range(2, 7):
        klien.post("/api/playbook/langkah", headers=h, json={"layanan_id": "imigrasi", "indeks": i, "selesai": True})
    assert klien.post("/api/pulihkan", headers=h, json={"layanan_id": "imigrasi"}).status_code == 200
    k = potret(klien, h)
    assert not any(s["id"] == "ancaman" for s in k["topologi"]["simpul"])
    assert all(l["status"] != "merah" for l in k["layanan"])


def test_reset_menaikkan_versi(klien):
    _, h = masuk(klien)
    v = potret(klien, h)["versi"]
    klien.post("/api/reset-demo", headers=h)
    assert potret(klien, h)["versi"] > v


# ---------- siaran langsung (Fase 2: satu dapur, satu Hub) ----------
def _teks(pesan) -> str:
    return "".join(p.decode() if isinstance(p, bytes) else p for p in pesan)


def test_siaran_mengantar_keadaan_lalu_menutup_rapi():
    KONFIG.umur_siaran_detik = 0  # tutup segera setelah hidangan pertama
    with TestClient(main.app) as klien:                # 'with' = lifespan jalan = dapur menyala
        _, h = masuk(klien)
        with klien.stream("GET", "/api/telemetri/siaran", headers=h) as r:
            assert r.status_code == 200
            assert r.headers["content-type"].startswith("text/event-stream")
            teks = r.read().decode()
    assert re.match(r"id: \d+\nevent: keadaan\ndata: \{", teks)
    assert '"alasan":"segarkan"' in teks
    assert SIARAN.jumlah("operator") == 0  # kursi dikembalikan


def test_siaran_berhenti_saat_logout():
    token, _ = masuk(TestClient(main.app))

    async def jalankan():
        async with main.umur_aplikasi(main.app):
            gen = main._alirkan(token, "operator")
            pertama = await gen.__anext__()
            cabut_token(token)  # setara dengan logout
            return pertama, [x async for x in gen]

    pertama, sisa = asyncio.run(jalankan())
    assert b"event: keadaan" in pertama
    assert '"alasan":"sesi"' in _teks(sisa[-1:])
    assert SIARAN.jumlah("operator") == 0


def test_batas_siaran_per_akun(klien):
    _, h = masuk(klien)
    for _ in range(KONFIG.maks_siaran_per_akun):
        assert SIARAN.masuk("operator")
    try:
        assert klien.get("/api/telemetri/siaran", headers=h).status_code == 429
    finally:
        for _ in range(KONFIG.maks_siaran_per_akun):
            SIARAN.keluar("operator")


# ---------- Fase 2: satu dapur untuk semua layar ----------
def _hitung_masakan(monkeypatch):
    hitung = {"n": 0}
    asli_potret, asli_detak = main.MENARA.potret, main.MENARA.detak

    def potret(*a, **k):
        hitung["n"] += 1
        return asli_potret(*a, **k)

    def detak(*a, **k):
        hitung["n"] += 1
        return asli_detak(*a, **k)

    monkeypatch.setattr(main.MENARA, "potret", potret)
    monkeypatch.setattr(main.MENARA, "detak", detak)
    return hitung


@pytest.mark.parametrize("jumlah_layar", [1, 60])
def test_biaya_masak_tidak_bertambah_dengan_jumlah_layar(monkeypatch, jumlah_layar):
    token, _ = masuk(TestClient(main.app))
    KONFIG.umur_siaran_detik = 2.2
    maks = KONFIG.maks_siaran_per_akun
    KONFIG.maks_siaran_per_akun = 1000
    hitung = _hitung_masakan(monkeypatch)

    async def jalankan():
        async with main.umur_aplikasi(main.app):
            async def satu_layar():
                return [x async for x in main._alirkan(token, "operator")]
            return await asyncio.gather(*(satu_layar() for _ in range(jumlah_layar)))

    try:
        hasil = asyncio.run(jalankan())
    finally:
        KONFIG.maks_siaran_per_akun = maks
    # ≈2,2 detik = ≈3 kali masak, berapa pun jumlah layarnya (dulu: 3 x jumlah layar)
    assert hitung["n"] <= 5
    assert all(b"event: keadaan" in p[0] for p in hasil)          # setiap layar tetap dapat potret
    assert len({p[0] for p in hasil}) == 1                         # ... dan bytes-nya identik
    assert SIARAN.jumlah("operator") == 0


async def _tunggu(kondisi, batas=6.0):
    """Fase 5: tunggu sampai kondisi benar (maks `batas` detik), bukan jeda tetap. Jeda tetap 1,3 detik
    gagal sesekali di komputer yang sedang sibuk/dingin, padahal perilakunya benar."""
    akhir = time.monotonic() + batas
    while not kondisi() and time.monotonic() < akhir:
        await asyncio.sleep(0.05)
    return kondisi()


def test_jam_simulasi_berjalan_walau_tanpa_layar():
    main.MENARA.osint.berikut = JAM["t"]                           # berita CTI jatuh tempo sekarang

    async def jalankan():
        async with main.umur_aplikasi(main.app):                  # tidak ada satu layar pun
            return await _tunggu(lambda: len(main.MENARA.osint.aktif) == 1)

    assert asyncio.run(jalankan())


def test_dapur_tetap_hidup_walau_satu_masakan_gagal(monkeypatch):
    asli = main.MENARA.potret
    gagal = {"sekali": True}

    def potret_rapuh(*a, **k):
        if gagal["sekali"]:
            gagal["sekali"] = False
            raise RuntimeError("simulasi kegagalan")
        return asli(*a, **k)

    monkeypatch.setattr(main.MENARA, "potret", potret_rapuh)

    async def jalankan():
        async with main.umur_aplikasi(main.app):
            return await _tunggu(lambda: main.HUB.keadaan_terakhir is not None)

    assert asyncio.run(jalankan())
    assert gagal["sekali"] is False                                # kegagalan memang terjadi lebih dulu


def test_hub_layar_baru_dapat_potret_terkini_dan_layar_lambat_pulih_sendiri():
    from app.siaran import Hub

    async def jalankan():
        hub = Hub(maks_antre=4)
        hub.siapkan()
        lama = hub.langganan()                                     # datang sebelum detak pertama
        hub.terbitkan(b"K1", None)                                 # detak pertama: potret disiarkan
        hub.terbitkan(b"K2", b"T2")                                # sesudahnya: hanya tambalan
        baru = hub.langganan()                                     # datang belakangan
        lambat = hub.langganan()                                   # tidak pernah membaca
        hub.terbitkan(b"K3", b"T3")
        ambil = lambda q: [q.get_nowait() for _ in range(q.qsize())]
        awal_lama, awal_baru = ambil(lama), ambil(baru)            # dua layar ini membaca tepat waktu
        for i in range(4, 12):
            hub.terbitkan(f"K{i}".encode(), f"T{i}".encode())
        return awal_lama, awal_baru, ambil(lambat)

    lama, baru, lambat = asyncio.run(jalankan())
    assert lama[:3] == [b"K1", b"T2", b"T3"]                       # yang lama: potret sekali, lalu ralat
    assert baru == [b"K2", b"T3"]                                  # yang baru: potret TERKINI, lalu ralat
    assert len(lambat) <= 4 and b"K" in b"".join(lambat)          # yang lambat: dipulihkan dengan potret


# ---------- Fase 3: tambalan delta ----------
def _urai(pesan: list) -> list[tuple[int, str, dict]]:
    """bytes/str SSE → [(id, jenis, data)]; komentar ': tetap-hidup' dilewati."""
    import json
    hasil = []
    for p in pesan:
        teks = p.decode() if isinstance(p, bytes) else p
        if teks.startswith(":"):
            continue
        baris = dict(b.split(": ", 1) for b in teks.strip().split("\n"))
        hasil.append((int(baris.get("id", -1)), baris["event"], json.loads(baris["data"])))
    return hasil


def test_layar_yang_menerapkan_tambalan_selalu_sama_dengan_potret_server(monkeypatch):
    """Uji ujung-ke-ujung: klien hanya menerima 1 potret + tambalan, lalu hasil rakitannya dibandingkan
    dengan potret utuh yang disimpan server. Insiden, SOAR, berita CTI, dan backup ikut diubah di tengahnya."""
    import json
    from app.delta import terapkan
    klien = TestClient(main.app)
    token, h = masuk(klien)
    KONFIG.umur_siaran_detik = 4.5
    # Fase 5: simpan potret utuh per NOMOR siaran. Pembanding = potret dengan nomor yang SAMA dengan
    # tambalan terakhir yang diterima layar, bukan "potret terakhir" (dapur bisa memasak sekali lagi
    # tepat saat siaran ditutup; browser sungguhan lalu menyambung ulang dan menerima potret utuh).
    potret_per_nomor = {}
    asli_terbitkan = main.HUB.terbitkan

    def terbitkan_dicatat(keadaan, tambalan):
        potret_per_nomor[int(keadaan.split(b"\n", 1)[0].split(b": ", 1)[1])] = keadaan
        return asli_terbitkan(keadaan, tambalan)

    monkeypatch.setattr(main.HUB, "terbitkan", terbitkan_dicatat)

    async def jalankan():
        async with main.umur_aplikasi(main.app):
            gen = main._alirkan(token, "operator")
            pesan = [await gen.__anext__()]
            aksi = [("/api/simulasi", {"layanan_id": "pajak", "skenario": "ransomware"}),
                    ("/api/cti/siarkan", {}),
                    ("/api/soar/jalankan", {"layanan_id": "pajak", "aksi": "isolasi"}),
                    ("/api/backup/catat", {"layanan_id": "imigrasi", "uji_pulih": True})]
            for jalur, data in aksi:
                await asyncio.to_thread(klien.post, jalur, headers=h, json=data)
                JAM["t"] += 1.3
                pesan.append(await gen.__anext__())
            pesan += [x async for x in gen]
            return pesan, main.HUB.keadaan_terakhir

    pesan, terakhir = asyncio.run(jalankan())
    urut = [p for p in _urai(pesan) if p[1] in ("keadaan", "tambalan")]
    assert urut[0][1] == "keadaan" and sum(1 for p in urut if p[1] == "keadaan") == 1
    nomor, dok = urut[0][0], urut[0][2]
    dok.pop("peristiwa")
    for eid, jenis, isi in urut[1:]:
        assert isi["dari"] == nomor and eid == nomor + 1               # rantai tidak putus
        dok, nomor = terapkan(dok, isi["ops"]), eid
    assert len(urut) >= 5                                             # 1 potret + tambalan dari 4 aksi
    server = json.loads(potret_per_nomor[nomor].decode().split("data: ", 1)[1])
    server.pop("peristiwa")
    assert dok == server


def test_tambalan_jauh_lebih_kecil_daripada_potret():
    import json
    from app.delta import beda
    klien = TestClient(main.app)
    _, h = masuk(klien)
    klien.post("/api/simulasi", headers=h, json={"layanan_id": "pajak", "skenario": "ransomware"})
    klien.post("/api/simulasi", headers=h, json={"layanan_id": "perizinan", "skenario": "ddos"})
    potret = lambda: {k: v for k, v in klien.get("/api/telemetri", headers=h).json().items()
                      if k not in ("peristiwa", "peran")}
    a = potret()
    JAM["t"] += 1
    b = potret()
    utuh, tambal = len(json.dumps(b)), len(json.dumps(beda(a, b)))
    assert tambal * 5 < utuh                                        # minimal 80% lebih hemat per detik


def test_beda_menangani_daftar_bergeser_dan_kunci_bergaris_miring():
    from app.delta import beda, terapkan
    lama = {"riwayat": list(range(48)), "a/b": {"x": 1}, "hapus": 1, "titik": [{"s": 1}, {"s": 2}, {"s": 3}]}
    baru = {"riwayat": list(range(1, 49)), "a/b": {"x": 2}, "titik": [{"s": 1}, {"s": 9}, {"s": 3}], "baru": True}
    ops = beda(lama, baru)
    assert ["r", "/riwayat", list(range(1, 49))] in ops            # bergeser → satu operasi, bukan 48
    assert ["r", "/a~1b/x", 2] in ops and ["d", "/hapus"] in ops and ["r", "/titik/1/s", 9] in ops
    assert terapkan(json_salin(lama), ops) == baru
    # daftar objek yang hanya berubah satu medan kecil → dikirim per elemen, bukan teks utuhnya
    berita = [{"judul": "x" * 300, "sisa_detik": i} for i in range(3)]
    ops = beda({"b": berita}, {"b": [{**x, "sisa_detik": x["sisa_detik"] - 1} for x in berita]})
    assert ops == [["r", "/b/0/sisa_detik", -1], ["r", "/b/1/sisa_detik", 0], ["r", "/b/2/sisa_detik", 1]]


def json_salin(x):
    import json
    return json.loads(json.dumps(x))
