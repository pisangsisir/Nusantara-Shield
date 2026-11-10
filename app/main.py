# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
main.py — Pintu masuk aplikasi Nusantara Shield (v4: + CTI, SOAR, Rantai Komando).

Cara membaca file ini untuk non-IT:
- Setiap fungsi yang diawali "@app.get" atau "@app.post" adalah sebuah LOKET.
  Browser datang ke loket, menyerahkan formulir, lalu menerima jawaban.
- "Depends(...)" adalah petugas yang wajib dilewati dulu sebelum sampai ke
  loket: satpam (cek login), antrean (rate limit), dan pemeriksa peran.
- Kelas "...Masuk" (pydantic) adalah FORMULIR baku. Isian yang tidak sesuai
  format otomatis ditolak sebelum diproses.
- MENARA (telemetri.py) adalah "dapur" pemantauan jaringan. Setiap loket yang
  mengubah state memberi tahu dapur (MENARA.ubah / MENARA.catat), lalu loket
  siaran (/api/telemetri/siaran) mengantar hasilnya ke semua browser.
- v3: loket /api/cti/siarkan (radio satpam), /api/soar/jalankan (tombol tindakan
  cepat) dan /api/soar/perketat (pengerasan proaktif berdasarkan prediksi).
- v5.1 (Pre-Authorized Containment): SOAR TIDAK dikunci menunggu izin. Laporan otomatis ke
  manajemen (simulasi) terbit setelah SEMUA tindakan pemutus selesai (Fase 1, F-02).
- Fase 1: aksi "isolasi" dan "pulihkan" dipisah (F-04); label dari app/istilah.py (F-10),
  disajikan ke browser lewat GET /api/istilah.
- Fase 2: SATU dapur untuk semua layar (dapur() + siaran.HUB, R1: F-05/F-06/F-07) dan
  middleware ASGI murni (BatasBody, HeaderKeamanan: F-08/F-15).
- Fase 3: dapur hanya menyiarkan TAMBALAN (delta.beda, R2); potret utuh hanya untuk layar baru.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import re
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from .audit import LOG
from .titik_periksa import TitikPeriksa
from .data_contoh import (BATAS_JAM_BACKUP, INDEKS_BERITA, INDEKS_INDIKATOR, LOG_PERINGATAN,
                          PLAYBOOK, SKENARIO, salin_layanan_awal)
from .keamanan import (KONFIG, MIN_SANDI, SIARAN, Akun, BatasBody, GalatAkun, HeaderKeamanan, akun_dari_token,
                       batasi, buat_token, butuh_izin, cabut_token, daftarkan_akun, kode_operator_sah,
                       pendaftaran_pengamat_terbuka, periksa_sandi, pengguna_saat_ini, pengguna_sesi, ringkasan_akun)
from .keamanan import cabut_sesi_lain, ganti_sandi as _ganti_sandi
from .delta import beda
from .siaran import HUB
from .lapsit import buat_pdf
from .istilah import ISTILAH
from .telemetri import (AKSI_GABUNGAN, ASET_BERPORT, MENARA, MIN_ALASAN_DARURAT, MIN_ALASAN_TUTUP, SEMUA_AKSI_SOAR,
                        STATUS_TUTUP)
from .ai_anomali import POLA
from .deteksi import JENIS_LATIHAN
from .impor_log import GalatImpor
from .drill import DRILL, KATALOG as KATALOG_DRILL, GalatDrill, awal_cerita, log_cerita

JALUR_IMPOR = "/api/deteksi/impor"
MAKS_ISI_IMPOR = 2_000_000                # karakter isi berkas log (≈2 MB)
BATAS_BODY_IMPOR = 2_600_000              # byte kiriman JSON untuk jalur impor (isi + pembungkus JSON)

FOLDER_STATIS = Path(__file__).resolve().parent.parent / "static"

log = logging.getLogger("nusantara")
JENDELA_GABUNG = 0.05   # detik: beberapa perubahan beruntun digabung jadi satu siaran


@contextlib.asynccontextmanager
async def umur_aplikasi(_app: FastAPI):
    """Menyalakan SATU dapur saat server hidup, dan mematikannya dengan rapi saat server berhenti."""
    loop = asyncio.get_running_loop()
    HUB.mulai()
    HUB.siapkan()

    def bangunkan() -> None:            # dipanggil MENARA.ubah() dari thread mana pun
        try:
            loop.call_soon_threadsafe(HUB.bangunkan)
        except RuntimeError:            # loop sudah ditutup (server sedang berhenti)
            pass

    MENARA.saat_ubah = bangunkan
    tugas = asyncio.create_task(dapur(), name="dapur")
    try:
        yield
    finally:
        MENARA.saat_ubah = None
        tugas.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await tugas


# Dokumentasi API otomatis (/docs) DIMATIKAN: tidak perlu memberi peta
# lengkap semua loket kepada orang asing.
app = FastAPI(title="Nusantara Shield", docs_url=None, redoc_url=None, openapi_url=None,
              lifespan=umur_aplikasi)

# Urutan middleware: yang ditambahkan TERAKHIR dijalankan PERTAMA (paling luar).
# Jalur masuk: HeaderKeamanan → TrustedHost → BatasBody → CORS → router.
app.add_middleware(
    CORSMiddleware,
    allow_origins=KONFIG.origin_diizinkan,   # hanya alamat yang terdaftar, BUKAN "*"
    allow_credentials=False,                  # token dikirim lewat header, bukan cookie
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(BatasBody, batas=KONFIG.batas_body_byte,    # F-08: sebelum router
                   khusus={JALUR_IMPOR: BATAS_BODY_IMPOR})    # Fase 3: hanya impor log boleh ≈2 MB
app.add_middleware(TrustedHostMiddleware, allowed_hosts=KONFIG.host_diizinkan)
app.add_middleware(HeaderKeamanan)                            # F-15: paling luar, ASGI murni
app.mount("/static", StaticFiles(directory=FOLDER_STATIS), name="static")

# --------------------------------------------------------------------------
# KEADAAN (state) DEMO — disimpan di memori, dijaga kunci agar tidak bentrok
# --------------------------------------------------------------------------
_kunci_state = threading.Lock()
LAYANAN = salin_layanan_awal()

# F-02: setiap laporan yang lahir (dari SOAR, antrean, ATAU centang manual) masuk log audit berantai.
# Fase 4: berikut rujukan bukti (nomor + SHA-256) atau ALASAN isolasi darurat bila bukti belum ada.
MENARA.saat_ir = lambda ir: LOG.catat("sistem", "IR_OTOMATIS", {
    "nomor": ir["nomor"], "uuid": ir["uuid"], "layanan": ir["layanan_id"],
    "kepada": " & ".join(ir["kepada"]), "tindakan": ", ".join(ir["tindakan"]),
    "bukti": ir["bukti"]["nomor"] if ir.get("bukti") else None,
    "bukti_sha256": ir["bukti"]["sha256"] if ir.get("bukti") else None,
    "darurat_alasan": ir["darurat"]["alasan"] if ir.get("darurat") else None,
    "darurat_hash_buku": ir["darurat"]["hash_buku"] if ir.get("darurat") else None})
# Fase 4: setiap halaman buku rantai bukti dicerminkan ke log audit (dua buku, dua rantai HMAC).
MENARA.saat_bukti = lambda petugas, aksi, detail: LOG.catat(petugas, aksi, detail)
# Titik periksa Ed25519 atas kedua buku (Dokumentasi Teknis §2.7): auditor memeriksa dengan kunci publik saja.
TITIK = TitikPeriksa({"audit_log": LOG, "rantai_bukti": MENARA.rantai.buku})


def _waktu() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _status(l: dict) -> tuple[str, str]:
    """Menentukan lampu hijau/kuning/merah beserta alasannya."""
    if l["insiden"]:
        return "merah", f"Insiden aktif: {l['insiden']['judul']}"
    if l["jam_sejak_backup"] > BATAS_JAM_BACKUP:
        return "kuning", f"Umur cadangan {l['jam_sejak_backup']} jam (batas {BATAS_JAM_BACKUP} jam)"
    if not l["backup_teruji"]:
        return "kuning", "Cadangan ada, tetapi belum pernah diuji pulih"
    return "hijau", "Normal; cadangan terbaru dan sudah diuji"


def _tampilan(l: dict) -> dict:
    status, alasan = _status(l)
    return {**l, "status": status, "alasan": alasan}


# --------------------------------------------------------------------------
# FORMULIR (validasi input) — extra="forbid": kolom tak dikenal ditolak
# --------------------------------------------------------------------------
class Formulir(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


IdLayanan = Literal["imigrasi", "perizinan", "pajak", "kesehatan", "listrik", "logistik"]
IdSkenario = Literal["ransomware", "backup_dimatikan", "ddos", "sabotase_ot"]


POLA_NAMA_AKUN = r"^[a-z][a-z0-9_]{2,19}$"   # sama dengan keamanan.POLA_NAMA


class LoginMasuk(Formulir):
    nama: str = Field(pattern=POLA_NAMA_AKUN)
    sandi: str = Field(min_length=1, max_length=128)


class DaftarMasuk(Formulir):
    """Pendaftaran mandiri. Peran operator WAJIB membawa kode undangan yang sah."""
    nama: str = Field(pattern=POLA_NAMA_AKUN)
    sandi: str = Field(min_length=MIN_SANDI, max_length=128)
    peran: Literal["pengamat", "operator"] = "pengamat"
    kode_operator: str | None = Field(default=None, max_length=128)


class BuatAkunMasuk(Formulir):
    """Dibuat oleh operator dari dasbor (tanpa kode undangan: operatornya sendiri yang bertanggung jawab)."""
    nama: str = Field(pattern=POLA_NAMA_AKUN)
    sandi: str = Field(min_length=MIN_SANDI, max_length=128)
    peran: Literal["pengamat", "operator"] = "pengamat"


class CariMasuk(Formulir):
    nilai: str = Field(min_length=3, max_length=253)


class SimulasiMasuk(Formulir):
    layanan_id: IdLayanan
    skenario: IdSkenario
    gangguan_bukti: bool = False   # Fase 4: latihan "agen forensik gagal" → hanya isolasi darurat yang bisa


class DaruratMasuk(Formulir):
    layanan_id: IdLayanan
    alasan: str = Field(min_length=MIN_ALASAN_DARURAT, max_length=500)


class LangkahMasuk(Formulir):
    layanan_id: IdLayanan
    indeks: int = Field(ge=0, le=20)
    selesai: bool


class LayananMasuk(Formulir):
    layanan_id: IdLayanan


@app.exception_handler(RequestValidationError)
async def _tolak_input(_: Request, err: RequestValidationError) -> JSONResponse:
    # Jawaban ringkas: sebut kolom yang salah tanpa memantulkan isi kiriman.
    kesalahan = [{"kolom": ".".join(str(x) for x in e["loc"][1:]), "pesan": e["msg"]}
                 for e in err.errors()]
    return JSONResponse({"detail": "Isian tidak valid", "kesalahan": kesalahan}, status_code=422)


@app.exception_handler(Exception)
async def _galat_umum(_: Request, __: Exception) -> JSONResponse:
    # Jangan pernah tampilkan detail galat internal ke pengguna.
    return JSONResponse({"detail": "Terjadi kesalahan internal"}, status_code=500)


# --------------------------------------------------------------------------
# PENGENAL JENIS INDIKATOR
# --------------------------------------------------------------------------
POLA_HASH = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")
POLA_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def kenali_jenis(nilai: str) -> str | None:
    """Menebak apakah input berupa IP, hash berkas, atau nama domain."""
    v = nilai.lower()
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if POLA_HASH.match(v):
        return "hash"
    if POLA_DOMAIN.match(v):
        return "domain"
    return None


# --------------------------------------------------------------------------
# LOKET-LOKET
# --------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
def halaman_utama() -> FileResponse:
    return FileResponse(FOLDER_STATIS / "index.html")


@app.get("/api/health", dependencies=[Depends(batasi("umum"))])
def kesehatan_aplikasi() -> dict:
    # Sengaja minimal: tidak membocorkan path, versi, atau isi basis data.
    return {"status": "ok"}


@app.get("/api/istilah", dependencies=[Depends(batasi("umum"))])
def istilah() -> dict:
    """Kamus label untuk browser (F-10). Publik karena hanya berisi label tampilan,
    dibutuhkan sebelum login (nama produk di halaman masuk)."""
    return ISTILAH


@app.post("/api/login", dependencies=[Depends(batasi("login"))])
def login(f: LoginMasuk) -> dict:
    akun = periksa_sandi(f.nama, f.sandi)
    if not akun:
        LOG.catat("tidak-dikenal", "LOGIN_GAGAL", {})  # nama yang dicoba tidak dicatat
        raise HTTPException(401, "Nama atau sandi salah")
    LOG.catat(akun.nama, "LOGIN", {"peran": akun.peran})
    return {"token": buat_token(akun), "nama": akun.nama, "peran": akun.peran,
            "berlaku_detik": KONFIG.masa_berlaku_token_detik, "wajib_ganti": akun.wajib_ganti}


class GantiSandiMasuk(Formulir):
    sandi_lama: str = Field(min_length=1, max_length=128)
    sandi_baru: str = Field(min_length=1, max_length=128)


@app.post("/api/akun/ganti-sandi", dependencies=[Depends(batasi("login"))])
def ganti_sandi(f: GantiSandiMasuk, request: Request, akun: Akun = Depends(pengguna_sesi)) -> dict:
    """Mengganti sandi sendiri. Wajib untuk akun bawaan pada pemasangan produksi sebelum dasbor terbuka.
    Dibatasi laju seperti login, karena sandi lama bisa ditebak lewat loket ini."""
    try:
        _ganti_sandi(akun, f.sandi_lama, f.sandi_baru)
    except GalatAkun as e:
        raise HTTPException(e.kode, e.pesan) from None
    dicabut = cabut_sesi_lain(akun.nama, request.headers.get("authorization", "").split(" ", 1)[-1])
    LOG.catat(akun.nama, "GANTI_SANDI", {"sesi_lain_dicabut": dicabut})   # sandi lama maupun baru tidak dicatat
    return {"ok": True, "wajib_ganti": False}


# --------------------------------------------------------------------------
# Fase 5 (audit #7): MANAJEMEN AKUN
# --------------------------------------------------------------------------
def _buat_akun(nama: str, sandi: str, peran: str, asal: str, oleh: str) -> dict:
    try:
        akun = daftarkan_akun(nama, sandi, peran, asal)
    except GalatAkun as e:
        raise HTTPException(e.kode, e.pesan) from None
    # Sandi TIDAK pernah dicatat; cukup siapa membuat akun apa, dengan cara apa.
    LOG.catat(oleh, "AKUN_DIBUAT", {"nama": akun.nama, "peran": akun.peran, "cara": asal})
    return {"nama": akun.nama, "peran": akun.peran, "dibuat": akun.dibuat}


@app.post("/api/akun/daftar", status_code=201, dependencies=[Depends(batasi("daftar"))])
def daftar_mandiri(f: DaftarMasuk) -> dict:
    """Pendaftaran tanpa login. Pengamat: terbuka (kecuali NS_DAFTAR_PENGAMAT=0).
    Operator: hanya dengan kode undangan NS_KODE_OPERATOR; tanpa variabel itu, tertutup sama sekali."""
    if f.peran == "operator":
        if not kode_operator_sah(f.kode_operator):
            LOG.catat("tidak-dikenal", "DAFTAR_OPERATOR_DITOLAK", {})
            raise HTTPException(403, "Akun Operator memerlukan kode undangan yang sah dari administrator")
        asal = "kode_undangan"
    else:
        if not pendaftaran_pengamat_terbuka():
            raise HTTPException(403, "Pendaftaran Pengamat sedang ditutup administrator")
        asal = "mandiri"
    return _buat_akun(f.nama, f.sandi, f.peran, asal, f.nama)


@app.post("/api/akun", status_code=201, dependencies=[Depends(batasi("ubah"))])
def buat_akun_oleh_operator(f: BuatAkunMasuk, akun: Akun = Depends(butuh_izin("kelola_akun"))) -> dict:
    return _buat_akun(f.nama, f.sandi, f.peran, "operator", akun.nama)


@app.get("/api/akun/ringkasan", dependencies=[Depends(batasi("umum"))])
def ringkasan_akun_operator(akun: Akun = Depends(butuh_izin("kelola_akun"))) -> dict:
    """Dasbor operator: jumlah pengamat terdaftar, yang sedang login, dan yang sedang memantau."""
    return ringkasan_akun()


@app.post("/api/logout", dependencies=[Depends(batasi("umum"))])
def logout(request: Request, akun: Akun = Depends(pengguna_sesi)) -> dict:
    token = request.headers.get("authorization", "").split(" ", 1)[-1]
    cabut_token(token)
    LOG.catat(akun.nama, "LOGOUT", {})
    return {"ok": True}


@app.get("/api/layanan", dependencies=[Depends(batasi("umum"))])
def daftar_layanan(akun: Akun = Depends(butuh_izin("lihat"))) -> dict:
    with _kunci_state:
        return {"layanan": [_tampilan(l) for l in LAYANAN.values()],
                "batas_jam_backup": BATAS_JAM_BACKUP, "peran": akun.peran}


@app.post("/api/indikator/cari", dependencies=[Depends(batasi("umum"))])
def cari_indikator(f: CariMasuk, akun: Akun = Depends(butuh_izin("lihat"))) -> dict:
    jenis = kenali_jenis(f.nilai)
    if jenis is None:
        raise HTTPException(422, "Format tidak dikenali. Masukkan IP, domain, atau hash (MD5/SHA-1/SHA-256).")
    temuan = INDEKS_INDIKATOR.get((jenis, f.nilai.lower()))
    # Minimisasi data: nilai mentah yang dicari TIDAK dicatat, hanya jenis & hasil.
    LOG.catat(akun.nama, "CARI_INDIKATOR",
              {"jenis": jenis, "cocok": bool(temuan), "id": temuan["id"] if temuan else None})
    return {"jenis": jenis, "cocok": bool(temuan), "indikator": temuan}


def _mulai_insiden(layanan_id: str, skenario: str, gangguan_bukti: bool) -> dict:
    """Memulai insiden latihan di satu layanan. Pemanggil WAJIB memegang _kunci_state."""
    l = LAYANAN[layanan_id]
    if l["insiden"]:
        raise HTTPException(409, "Layanan ini sudah dalam insiden aktif")
    langkah = PLAYBOOK[skenario]
    mulai = datetime.now(timezone.utc)
    # Log peringatan sintetis: waktu tiap kejadian dihitung mundur dari awal insiden.
    log = [{"waktu": (mulai + timedelta(minutes=m)).isoformat(timespec="seconds"),
            "tingkat": t, "pesan": p} for m, t, p in LOG_PERINGATAN[skenario]]
    l["insiden"] = {"id": uuid.uuid4().hex[:12], "skenario": skenario, "judul": SKENARIO[skenario],
                    "gangguan_bukti": gangguan_bukti,
                    "mulai": mulai.isoformat(timespec="seconds"), "log_peringatan": log,
                    "langkah": langkah, "langkah_selesai": [False] * len(langkah)}
    # Beri tahu dapur: peta, radar, gauge, dan log semua browser ikut berubah.
    MENARA.insiden_dimulai(LAYANAN, layanan_id, skenario, SKENARIO[skenario], LOG_PERINGATAN[skenario])
    return _tampilan(l)


@app.post("/api/simulasi", dependencies=[Depends(batasi("ubah"))])
def simulasi_insiden(f: SimulasiMasuk, akun: Akun = Depends(butuh_izin("ubah"))) -> dict:
    with _kunci_state:
        hasil = _mulai_insiden(f.layanan_id, f.skenario, f.gangguan_bukti)
    LOG.catat(akun.nama, "SIMULASI_INSIDEN", {"layanan": f.layanan_id, "skenario": f.skenario,
                                             "gangguan_bukti": f.gangguan_bukti})
    return hasil


@app.post("/api/playbook/langkah", dependencies=[Depends(batasi("ubah"))])
def tandai_langkah(f: LangkahMasuk, akun: Akun = Depends(butuh_izin("ubah"))) -> dict:
    with _kunci_state:
        # F-04 + Fase 4: centang manual tunduk pada kunci urutan yang SAMA dengan tombol SOAR:
        # bukti → pemutusan → (cocokkan hash) → pemulihan. Efek di peta, beban, dan MTTC ikut dihitung.
        try:
            MENARA.tandai_manual(LAYANAN, f.layanan_id, f.indeks, f.selesai, akun.nama)
        except IndexError as e:
            raise HTTPException(422, str(e)) from None
        except ValueError as e:
            raise HTTPException(409, str(e)) from None
        hasil = _tampilan(LAYANAN[f.layanan_id])
    LOG.catat(akun.nama, "LANGKAH_PLAYBOOK",
              {"layanan": f.layanan_id, "langkah": f.indeks + 1, "selesai": f.selesai})
    return hasil


@app.post("/api/pulihkan", dependencies=[Depends(batasi("ubah"))])
def pulihkan_layanan(f: LayananMasuk, akun: Akun = Depends(butuh_izin("ubah"))) -> dict:
    with _kunci_state:
        l = LAYANAN[f.layanan_id]
        ins = l["insiden"]
        if not ins:
            raise HTTPException(409, "Tidak ada insiden aktif di layanan ini")
        if not all(ins["langkah_selesai"]):
            # Disiplin prosedur: layanan baru boleh dinyatakan pulih bila semua langkah beres.
            raise HTTPException(409, "Selesaikan semua langkah playbook sebelum memulihkan")
        try:   # Fase 4: memulihkan dari cadangan = menghapus jejak penyerang → cocokkan hash bukti dulu
            MENARA.verifikasi_untuk_pemulihan(LAYANAN, f.layanan_id, akun.nama)
        except ValueError as e:
            raise HTTPException(409, str(e)) from None
        l["insiden"] = None
        l["jam_sejak_backup"], l["backup_teruji"] = 0, True  # dipulihkan dari cadangan teruji
        MENARA.insiden_ditutup(f.layanan_id)
        MENARA.catat("info", f"{l['nama']} dipulihkan dari cadangan teruji. Insiden latihan ditutup.",
                     layanan=f.layanan_id)
        MENARA.ubah()
        hasil = _tampilan(l)
    LOG.catat(akun.nama, "PULIHKAN_LAYANAN", {"layanan": f.layanan_id, "skenario": ins["skenario"]})
    return hasil


class BackupMasuk(Formulir):
    layanan_id: IdLayanan
    uji_pulih: bool  # True = cadangan sudah dicoba dipulihkan dan berhasil dibaca


class WaktuMasuk(Formulir):
    jam: int = Field(ge=1, le=72)


@app.post("/api/backup/catat", dependencies=[Depends(batasi("ubah"))])
def catat_backup(f: BackupMasuk, akun: Akun = Depends(butuh_izin("ubah"))) -> dict:
    """Fitur kepatuhan pencadangan (prioritas hasil riset kasus PDNS 2024).

    Analogi: buku piket fotokopi arsip. Petugas mencatat kapan fotokopi
    terakhir dibuat, dan apakah fotokopi itu sudah dicoba dibaca ulang.
    Cadangan yang tidak pernah diuji ibarat payung yang belum pernah dibuka:
    baru ketahuan bolong saat hujan.
    """
    with _kunci_state:
        l = LAYANAN[f.layanan_id]
        l["jam_sejak_backup"] = 0
        l["backup_teruji"] = f.uji_pulih
        MENARA.catat("info" if f.uji_pulih else "sedang",
                     f"Cadangan {l['nama']} dicatat" + (" dan sudah diuji pulih" if f.uji_pulih else " (belum diuji)"),
                     layanan=f.layanan_id)
        MENARA.ubah()
        hasil = _tampilan(l)
    LOG.catat(akun.nama, "CATAT_BACKUP", {"layanan": f.layanan_id, "uji_pulih": f.uji_pulih})
    return hasil


@app.post("/api/demo/majukan-waktu", dependencies=[Depends(batasi("ubah"))])
def majukan_waktu(f: WaktuMasuk, akun: Akun = Depends(butuh_izin("ubah"))) -> dict:
    """Mesin waktu demo: memajukan jam agar juri bisa melihat cadangan yang
    'menua' berubah dari hijau ke kuning tanpa menunggu sehari penuh."""
    with _kunci_state:
        for l in LAYANAN.values():
            l["jam_sejak_backup"] = min(l["jam_sejak_backup"] + f.jam, 9999)
        MENARA.catat("sedang", f"Mesin waktu demo: jam dimajukan {f.jam} jam")
        MENARA.ubah()
        hasil = [_tampilan(l) for l in LAYANAN.values()]
    LOG.catat(akun.nama, "MAJUKAN_WAKTU_DEMO", {"jam": f.jam})
    return {"layanan": hasil}


@app.post("/api/reset-demo", dependencies=[Depends(batasi("ubah"))])
def reset_demo(akun: Akun = Depends(butuh_izin("ubah"))) -> dict:
    global LAYANAN
    with _kunci_state:
        LAYANAN = salin_layanan_awal()
        MENARA.reset()
        MENARA.catat("sedang", "Demo direset ke kondisi awal")
        drill_batal = DRILL.batal()                 # riwayat hasil drill tetap disimpan
    LOG.catat(akun.nama, "RESET_DEMO", {})  # log audit sengaja TIDAK ikut dihapus
    if drill_batal:
        LOG.catat(akun.nama, "DRILL_DIBATALKAN", {"drill": drill_batal, "alasan": "reset demo"})
    return {"ok": True}


# --------------------------------------------------------------------------
# TELEMETRI: hidangan untuk dasbor (Executive Overview, radar, gauge, log)
# --------------------------------------------------------------------------
@app.get("/api/telemetri", dependencies=[Depends(batasi("umum"))])
def telemetri(akun: Akun = Depends(butuh_izin("lihat"))) -> dict:
    """Satu potret lengkap. Dipakai saat pertama tersambung dan sebagai
    cadangan (polling) bila siaran langsung terputus."""
    with _kunci_state:
        hasil = MENARA.potret(LAYANAN, _tampilan)
    return {**hasil, "peran": akun.peran}


def _sse_mentah(jenis: str, json_satu_baris: str, eid: int | None = None) -> str:
    """Format Server-Sent Events: [id:], event:, data: (JSON satu baris), lalu baris kosong."""
    kepala = f"id: {eid}\n" if eid is not None else ""
    return f"{kepala}event: {jenis}\ndata: {json_satu_baris}\n\n"


def _sse(jenis: str, data: dict, eid: int | None = None) -> str:
    return _sse_mentah(jenis, json.dumps(data, separators=(",", ":"), ensure_ascii=False), eid)


async def dapur() -> None:
    """SATU-SATUNYA pemasak (Fase 2, R1) yang kini hanya menyiarkan RALAT (Fase 3, R2).

    Tiap detik (atau ≈50 ms setelah ada perubahan):
      1. masak potret utuh SEKALI, di thread pekerja (kunci tidak pernah dipegang event loop);
      2. bandingkan dengan potret sebelumnya → daftar operasi kecil (delta.beda);
      3. peristiwa log dikirim apa adanya (append-only), bukan dibandingkan;
      4. siarkan tambalan ke semua layar; simpan potret utuh hanya untuk layar yang baru datang.
    Tick tanpa perubahan apa pun tidak menyiarkan apa-apa."""
    lalu: dict | None = None            # potret sebelumnya (tanpa 'peristiwa'), hasil json.loads
    nomor, seq, terakhir = 0, 0, 0.0

    def masak(dasar: dict | None, nomor_baru: int, seq_lalu: int):
        with _kunci_state:                                     # kunci dipegang di THREAD PEKERJA
            data = MENARA.potret(LAYANAN, _tampilan)
        # salinan dalam lewat JSON: potret berbagi objek dengan state hidup, jadi tidak boleh disimpan langsung
        teks = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
        struktur = json.loads(teks)
        peristiwa_baru = [e for e in struktur.pop("peristiwa") if e["seq"] > seq_lalu]
        keadaan = _sse_mentah("keadaan", teks, nomor_baru).encode()
        if dasar is None:
            return struktur, data["seq_terakhir"], keadaan, None
        ops = beda(dasar, struktur)
        if not ops and not peristiwa_baru:
            return struktur, data["seq_terakhir"], keadaan, b""          # tidak ada yang berubah
        tambalan = _sse("tambalan", {"dari": nomor_baru - 1, "ops": ops, "peristiwa": peristiwa_baru},
                        nomor_baru).encode()
        return struktur, data["seq_terakhir"], keadaan, tambalan

    while True:
        try:
            await asyncio.wait_for(HUB.bangun.wait(), timeout=max(0.0, 1.0 - (time.monotonic() - terakhir)))
            await asyncio.sleep(JENDELA_GABUNG)    # beberapa ubah() beruntun = satu siaran
        except asyncio.TimeoutError:
            pass                                   # tidak ada perubahan: detak rutin 1x per detik
        HUB.bangun.clear()
        terakhir = time.monotonic()
        try:
            hasil = await asyncio.to_thread(masak, lalu, nomor + 1, seq)
        except Exception:                          # dapur tidak boleh mati karena satu masakan gagal
            log.exception("dapur gagal memasak; dicoba lagi pada detak berikutnya")
            continue
        struktur, seq_baru, keadaan, tambalan = hasil
        if tambalan == b"":
            continue                               # nomor tidak naik: rantai tetap utuh
        nomor, lalu, seq = nomor + 1, struktur, seq_baru
        HUB.terbitkan(keadaan, tambalan)


async def _alirkan(token: str, nama: str):
    """Pelayan TIPIS untuk satu layar: tidak memasak apa pun, hanya meneruskan bytes dari Hub.
    - Layar baru menerima SATU potret utuh terkini, lalu tambalan-tambalan sesudahnya (Fase 3).
    - Tiap ≈2 detik token diperiksa ulang: logout/kedaluwarsa = siaran ditutup.
    - Komentar SSE ': tetap-hidup' menjaga proxy tidak memutus sambungan yang sedang sepi."""
    # Kursi dihitung DI DALAM generator: bila browser pergi sebelum siaran dimulai,
    # kursi tidak pernah terpakai sehingga hitungan tidak bocor.
    if not SIARAN.masuk(nama):
        yield _sse("tutup", {"alasan": "penuh"})
        return
    q = HUB.langganan()
    cek_terakhir = time.monotonic()
    batas_umur = cek_terakhir + KONFIG.umur_siaran_detik
    try:
        while True:
            try:
                yield await asyncio.wait_for(q.get(), timeout=2.0)
            except asyncio.TimeoutError:
                yield ": tetap-hidup\n\n"
            sekarang = time.monotonic()
            if sekarang - cek_terakhir >= 2 or sekarang >= batas_umur:
                cek_terakhir = sekarang
                if akun_dari_token(token) is None:
                    yield _sse("tutup", {"alasan": "sesi"})
                    return
                if sekarang >= batas_umur:
                    yield _sse("tutup", {"alasan": "segarkan"})  # browser akan menyambung ulang
                    return
    finally:
        HUB.lepas(q)
        SIARAN.keluar(nama)  # selalu dijalankan, termasuk saat browser ditutup mendadak


@app.get("/api/telemetri/siaran", dependencies=[Depends(batasi("umum"))])
async def siaran_telemetri(request: Request, akun: Akun = Depends(butuh_izin("lihat"))) -> StreamingResponse:
    """Siaran langsung (Server-Sent Events) yang tetap memakai token di header.
    Sengaja TIDAK memakai token di URL (?token=...) karena URL mudah tercatat
    di riwayat browser dan log server."""
    token = request.headers.get("authorization", "").split(" ", 1)[-1]
    if SIARAN.jumlah(akun.nama) >= KONFIG.maks_siaran_per_akun:
        raise HTTPException(429, "Terlalu banyak siaran terbuka untuk akun ini")
    return StreamingResponse(_alirkan(token, akun.nama), media_type="text/event-stream",
                             headers={"X-Accel-Buffering": "no"})


# --------------------------------------------------------------------------
# v3: THREAT INTELLIGENCE & SOAR
# --------------------------------------------------------------------------
IdAksiSoar = Literal[tuple(SEMUA_AKSI_SOAR + AKSI_GABUNGAN)]
IdAset = Literal[tuple(ASET_BERPORT)]


class CtiMasuk(Formulir):
    berita_id: str | None = Field(default=None, pattern=r"^CTI-\d{3}$")


class SoarMasuk(Formulir):
    layanan_id: IdLayanan
    aksi: IdAksiSoar


class PerketatMasuk(Formulir):
    aset_id: IdAset


class TutupPeringatanMasuk(Formulir):
    aset_id: IdAset
    status: Literal[tuple(STATUS_TUTUP)]
    alasan: str = Field(min_length=MIN_ALASAN_TUTUP, max_length=500)


IdPolaAI = Literal[tuple(POLA)]


class LatihanAIMasuk(Formulir):
    aset_id: IdAset
    pola: IdPolaAI | None = None


class LatihanDeteksiMasuk(Formulir):
    jenis: Literal[tuple(JENIS_LATIHAN)]
    aset_id: IdAset | None = None


class ImporLogMasuk(Formulir):
    nama: str = Field(min_length=1, max_length=120)
    isi: str = Field(min_length=1, max_length=MAKS_ISI_IMPOR)
    aset_id: IdAset | None = None            # sasaran baris auth.log (bawaan: Akses admin SSH)


@app.post("/api/cti/siarkan", dependencies=[Depends(batasi("ubah"))])
def siarkan_cti(f: CtiMasuk, akun: Akun = Depends(butuh_izin("ubah"))) -> dict:
    """Radio satpam: siarkan berita ancaman berikutnya SEKARANG (untuk mengatur tempo demo).
    Tanpa tombol ini pun berita tetap terbit otomatis secara berkala."""
    if f.berita_id and f.berita_id not in INDEKS_BERITA:
        raise HTTPException(404, "Berita tidak ada di katalog")
    with _kunci_state:
        b = MENARA.siarkan_berita(LAYANAN, f.berita_id)
        hasil = {"id": b["id"], "judul": b["judul"], "korelasi": b.get("korelasi", [])}
    LOG.catat(akun.nama, "CTI_SIARKAN", {"berita": b["id"], "cocok": len(hasil["korelasi"])})
    return hasil


@app.post("/api/soar/jalankan", dependencies=[Depends(batasi("ubah"))])
def jalankan_soar(f: SoarMasuk, akun: Akun = Depends(butuh_izin("ubah"))) -> dict:
    """Tombol tindakan cepat — PRE-AUTHORIZED: tidak menunggu izin.
    aksi="isolasi"  → hanya tindakan pemutus, berurutan; laporan terbit setelah semuanya selesai.
    aksi="pulihkan" → hanya bila syarat_pemulihan() terpenuhi (409 + alasan bila belum).
    Pencatatan laporan ke log audit dilakukan kait MENARA.saat_ir, bukan di sini."""
    with _kunci_state:
        try:
            hasil = MENARA.jalankan_soar(LAYANAN, f.layanan_id, f.aksi, akun.nama)
        except ValueError as e:
            raise HTTPException(409, str(e)) from None
        hasil["layanan"] = _tampilan(LAYANAN[f.layanan_id])
    LOG.catat(akun.nama, "SOAR_JALANKAN", {"layanan": f.layanan_id, "aksi": f.aksi})
    return hasil


@app.post("/api/soar/darurat", dependencies=[Depends(batasi("ubah"))])
def isolasi_darurat(f: DaruratMasuk, akun: Akun = Depends(butuh_izin("ubah"))) -> dict:
    """Fase 4 — EMERGENCY OVERRIDE: putus jaringan tanpa menunggu bukti. Alasan wajib; tercatat di
    buku rantai bukti, log audit (kait saat_bukti), dan laporan ke manajemen."""
    with _kunci_state:
        try:
            hasil = MENARA.isolasi_darurat(LAYANAN, f.layanan_id, f.alasan, akun.nama)
        except ValueError as e:
            raise HTTPException(409, str(e)) from None
        hasil["layanan"] = _tampilan(LAYANAN[f.layanan_id])
    return hasil


@app.get("/api/bukti", dependencies=[Depends(batasi("umum"))])
def lihat_buku_bukti(akun: Akun = Depends(butuh_izin("lihat"))) -> dict:
    """Fase 4: berita acara barang bukti (terbaru di atas) + hasil verifikasi rantai."""
    return {"entri": MENARA.rantai.daftar(50), "verifikasi": MENARA.rantai.buku.verifikasi(),
            "sementara": MENARA.rantai.buku.sementara}


@app.post("/api/soar/perketat", dependencies=[Depends(batasi("ubah"))])
def perketat_aset(f: PerketatMasuk, akun: Akun = Depends(butuh_izin("ubah"))) -> dict:
    """SOAR proaktif: pengerasan aset yang DIPREDIKSI akan diserang, sebelum serangan datang."""
    with _kunci_state:
        try:
            MENARA.perketat(LAYANAN, f.aset_id)
        except ValueError as e:
            raise HTTPException(409, str(e)) from None
    LOG.catat(akun.nama, "SOAR_PERKETAT", {"aset": f.aset_id})
    return {"ok": True, "aset_id": f.aset_id}


@app.post("/api/peringatan/tutup", dependencies=[Depends(batasi("ubah"))])
def tutup_peringatan(f: TutupPeringatanMasuk, akun: Akun = Depends(butuh_izin("ubah"))) -> dict:
    """Triase: Operator menutup peringatan WASPADA (selesai ditangani / alarm keliru) dengan alasan tertulis.
    Tidak ada yang dihapus: penutupan dicatat di buku rantai bukti dan log audit (kait saat_bukti)."""
    with _kunci_state:
        try:
            return MENARA.tutup_peringatan(LAYANAN, f.aset_id, f.status, f.alasan, akun.nama)
        except ValueError as e:
            raise HTTPException(409, str(e)) from None


@app.post("/api/deteksi/latihan", dependencies=[Depends(batasi("ubah"))])
def latihan_deteksi(f: LatihanDeteksiMasuk, akun: Akun = Depends(butuh_izin("ubah"))) -> dict:
    """Mesin deteksi aturan (app/deteksi.py): putar peristiwa mentah sintetis (login / koneksi). Temuan lahir dari aturan dengan
    ambang terbuka (app/deteksi.py) dan hanya menaikkan status; memutus jaringan tetap keputusan Operator."""
    with _kunci_state:
        try:
            hasil = MENARA.latihan_deteksi(LAYANAN, f.jenis, f.aset_id)
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
    LOG.catat(akun.nama, "DETEKSI_LATIHAN", {"jenis": f.jenis, "aset": hasil["aset_id"]})
    return hasil


@app.post(JALUR_IMPOR, dependencies=[Depends(batasi("impor"))])
def impor_log(f: ImporLogMasuk, akun: Akun = Depends(butuh_izin("ubah"))) -> dict:
    """Fase 3 — impor log ASLI secara luring (auth.log OpenSSH, log firewall UFW/iptables, atau CSV). Aturan yang sama
    dengan latihan menilainya; temuan hanya menaikkan WASPADA. Log audit mencatat nama berkas dan jumlah saja,
    bukan isi log."""
    nama = re.sub(r"[^\w.\- ]", "_", f.nama.replace("\\", "/").rsplit("/", 1)[-1])[:80] or "berkas"
    try:   # v5.4.1 (audit): berkas diurai DI LUAR kunci keadaan, jadi berkas besar tidak membekukan dasbor layar lain
        terurai = MENARA.urai_log(f.isi, f.aset_id or "ssh")
    except (GalatImpor, ValueError) as e:
        raise HTTPException(422, str(e)) from None
    with _kunci_state:
        try:
            hasil = MENARA.impor_log(LAYANAN, nama, f.isi, f.aset_id or "ssh", terurai=terurai)
        except (GalatImpor, ValueError) as e:
            raise HTTPException(422, str(e)) from None
    LOG.catat(akun.nama, "IMPOR_LOG", {"berkas": nama, "baris": hasil["baris"], "dikenali": hasil["dikenali"],
                                       "temuan": len(hasil["temuan"])})
    return hasil


@app.post("/api/ai/latihan", dependencies=[Depends(batasi("ubah"))])
def latihan_ai(f: LatihanAIMasuk, akun: Akun = Depends(butuh_izin("ubah"))) -> dict:
    """AI lokal: suntikkan pola lalu lintas tidak wajar (data sintetis) ke satu aset, lalu mesin
    deteksi anomali (Isolation Forest, berjalan di server ini) menilainya. Tidak ada panggilan ke luar."""
    with _kunci_state:
        hasil = MENARA.latihan_ai(LAYANAN, f.aset_id, f.pola)
    LOG.catat(akun.nama, "AI_LATIHAN", {"aset": f.aset_id, "pola": hasil["pola"]})
    return hasil


# --------------------------------------------------------------------------
# DRILL KESIAPAN (app/drill.py): latihan tanggap insiden untuk Operator, dinilai dari jejak yang tercatat
# --------------------------------------------------------------------------
class DrillMulaiMasuk(Formulir):
    kode: Literal[tuple(KATALOG_DRILL)]


class DrillJawabMasuk(Formulir):
    no: int = Field(ge=0, le=3)
    pilihan: Literal["a", "b", "c", "d"]


@app.get("/api/drill", dependencies=[Depends(batasi("umum"))])
def lihat_drill(akun: Akun = Depends(butuh_izin("lihat"))) -> dict:
    """Katalog, drill yang sedang berjalan (tanpa kunci jawaban yang belum dijawab), dan riwayat hasil."""
    with _kunci_state:
        return {"katalog": DRILL.katalog(), "aktif": DRILL.tampil(), "riwayat": list(DRILL.riwayat)}


@app.post("/api/drill/mulai", dependencies=[Depends(batasi("ubah"))])
def mulai_drill(f: DrillMulaiMasuk, akun: Akun = Depends(butuh_izin("ubah"))) -> dict:
    """Log cerita sintetis lewat jalur impor yang sama dengan log asli, lalu insiden latihan di layanan sasaran."""
    k = KATALOG_DRILL[f.kode]
    with _kunci_state:
        if DRILL.aktif:
            raise HTTPException(409, f"Drill {DRILL.aktif['id']} masih berjalan: selesaikan dulu")
        if LAYANAN[k["layanan_id"]]["insiden"]:
            raise HTTPException(409, f"{LAYANAN[k['layanan_id']]['nama']} masih dalam insiden: pulihkan dulu")
        awal = awal_cerita(f.kode, time.time())     # ≈4 menit sebelum drill, atau jam tetap skenario OT
        teks = log_cerita(f.kode, awal)
        nama = f"drill-{f.kode}.log"
        impor = MENARA.impor_log(LAYANAN, nama, teks, k["aset_ssh"])
        _mulai_insiden(k["layanan_id"], k["skenario"], False)
        aktif = DRILL.mulai(f.kode, akun.nama, teks, awal, impor)
    LOG.catat(akun.nama, "IMPOR_LOG", {"berkas": nama, "baris": impor["baris"], "dikenali": impor["dikenali"],
                                       "temuan": len(impor["temuan"])})
    LOG.catat(akun.nama, "SIMULASI_INSIDEN", {"layanan": k["layanan_id"], "skenario": k["skenario"],
                                             "gangguan_bukti": False})
    LOG.catat(akun.nama, "DRILL_MULAI", {"drill": aktif["id"], "kode": f.kode, "layanan": k["layanan_id"],
                                         "temuan": len(impor["temuan"])})
    return {"aktif": aktif}


@app.post("/api/drill/jawab", dependencies=[Depends(batasi("ubah"))])
def jawab_drill(f: DrillJawabMasuk, akun: Akun = Depends(butuh_izin("ubah"))) -> dict:
    with _kunci_state:
        try:
            hasil = DRILL.jawab(f.no, f.pilihan)
        except GalatDrill as e:
            raise HTTPException(409, str(e)) from None
        drill_id = DRILL.aktif["id"]
    # isi pilihan tidak dicatat: cukup benar/salah per fase
    LOG.catat(akun.nama, "DRILL_JAWAB", {"drill": drill_id, "no": f.no + 1, "fase": hasil["fase"],
                                         "benar": hasil["benar"]})
    return hasil


@app.post("/api/drill/selesai", dependencies=[Depends(batasi("ubah"))])
def selesai_drill(akun: Akun = Depends(butuh_izin("ubah"))) -> dict:
    """Nilai dihitung dari jejak respons yang tercatat sistem (MTTC, buku bukti, isolasi darurat)."""
    with _kunci_state:
        if not DRILL.aktif:
            raise HTTPException(409, "Tidak ada drill yang sedang berjalan")
        respons = MENARA.respons(LAYANAN, DRILL.aktif["layanan_id"])
        hasil = DRILL.selesai(respons, akun.nama)
        MENARA.catat("info", f"{hasil['id']} selesai: nilai kesiapan {hasil['nilai']}/100 ({hasil['huruf']}) "
                             f"· latihan, data sintetis", layanan=hasil["layanan_id"])
        MENARA.ubah()
    LOG.catat(akun.nama, "DRILL_SELESAI", {"drill": hasil["id"], "nilai": hasil["nilai"], "huruf": hasil["huruf"],
                                           "benar": hasil["benar"], "mttc_detik": hasil["mttc_detik"],
                                           "darurat": hasil["darurat"], "deteksi_lengkap": hasil["deteksi_lengkap"]})
    return {"hasil": hasil}


# --------------------------------------------------------------------------
# v5.1: QUICK CALL (PIC teknis cabang)
# --------------------------------------------------------------------------
@app.post("/api/komando/panggil", dependencies=[Depends(batasi("ubah"))])
def quick_call(f: LayananMasuk, akun: Akun = Depends(butuh_izin("ubah"))) -> dict:
    """QUICK CALL (simulasi) ke PIC teknis cabang: memberi tahu bahwa sistemnya sedang
    diisolasi agar tidak di-restart. Tidak menghubungi siapa pun; hanya dicatat."""
    with _kunci_state:
        hasil = MENARA.panggil(LAYANAN, f.layanan_id, akun.nama)
    LOG.catat(akun.nama, "QUICK_CALL", {"layanan": f.layanan_id, "pic": hasil["jabatan"]})
    return hasil


@app.get("/api/audit", dependencies=[Depends(batasi("umum"))])
def lihat_audit(akun: Akun = Depends(butuh_izin("lihat"))) -> dict:
    return {"entri": LOG.daftar(50), "sementara": LOG.sementara}


@app.get("/api/audit/verifikasi", dependencies=[Depends(batasi("umum"))])
def verifikasi_audit(akun: Akun = Depends(butuh_izin("lihat"))) -> dict:
    return {**LOG.verifikasi(), "titik_periksa": TITIK.ringkasan()}


@app.post("/api/lapsit", dependencies=[Depends(batasi("pdf"))])
def ekspor_lapsit(akun: Akun = Depends(butuh_izin("lihat"))) -> Response:
    with _kunci_state:
        data = [_tampilan(l) for l in LAYANAN.values()]
        rincian = MENARA.rincian_lapsit(LAYANAN)      # antrean SOAR & deteksi diproses dulu
        peringatan = MENARA.peringatan_lapsit(LAYANAN)
    LOG.catat(akun.nama, "EKSPOR_LAPSIT", {"jumlah_layanan": len(data)})
    titik = TITIK.buat("EKSPOR_LAPSIT")
    with _kunci_state:
        drill = list(DRILL.riwayat)[:3]
    pdf = buat_pdf(data, LOG.verifikasi(), akun.nama, peringatan, rincian, titik=TITIK.ringkasan(titik), drill=drill)
    nama_berkas = f"LAPSIT-NusantaraShield-{datetime.now(timezone.utc):%Y%m%d-%H%M}.pdf"
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{nama_berkas}"'})
