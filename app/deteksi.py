# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
Mesin deteksi aturan — membaca PERISTIWA MENTAH (upaya login, koneksi jaringan, dan perintah Modbus ke
zona kendali OT), lalu menyimpulkan temuan. Label MITRE ATT&CK tiap aturan ada di app/mitre.py.

Analogi: petugas jaga yang membaca buku tamu. Satu tamu salah menyebut nama sekali itu wajar; orang yang
sama mencoba 8 nama berbeda dalam satu menit patut dicurigai. Orang yang mengetuk 15 pintu berbeda dalam
10 detik sedang mengintai, bukan bertamu.

Prinsip:
- Peristiwa di purwarupa adalah DATA LATIHAN SINTETIS; ATURANNYA nyata, sederhana, dan ambangnya terbuka
  (ATURAN di bawah). Tidak ada peringatan yang "disuntikkan": setiap temuan lahir dari hitungan peristiwa.
- Temuan hanya MENAIKKAN peluang serangan aset (Kunci 1, mesin). Memutus jaringan tetap keputusan
  Operator (Kunci 2) — modul ini tidak punya jalur ke tindakan pemutus apa pun.
- Sepenuhnya defensif: modul ini hanya membaca catatan peristiwa; ia tidak memindai atau menghubungi apa pun.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

# Ambang terbuka. jendela = detik; peluang = sumbangan ke peluang serangan aset (digabung 1 − Π(1 − p)).
ATURAN: dict[str, dict] = {
    "login_gagal": {"nama": "Percobaan login gagal berulang", "ambang": 8, "jendela": 60,
                    "keparahan": "sedang", "peluang": 0.60},
    "login_tembus": {"nama": "Login berhasil setelah rentetan gagal", "jendela": 120,
                     "keparahan": "tinggi", "peluang": 0.85},
    "pindai_port": {"nama": "Pemindaian port", "ambang": 15, "jendela": 10,
                    "keparahan": "tinggi", "peluang": 0.35},
    # IT/OT: aturan deterministik untuk zona kendali (Modbus/TCP port 502)
    "ot_tanpa_izin": {"nama": "Koneksi IT ke zona kendali OT tanpa izin", "jendela": 600,
                      "keparahan": "tinggi", "peluang": 0.50},
    "tulis_ot_luar_jadwal": {"nama": "Perintah tulis Modbus di luar jendela pemeliharaan", "jendela": 60,
                             "keparahan": "kritis", "peluang": 0.70},
    "rantai_it_ot": {"nama": "Rantai IT ke OT: koneksi tanpa izin disusul perintah tulis", "jendela": 600,
                     "keparahan": "kritis", "peluang": 0.90},
}
MASA_AKTIF = 300   # detik sejak peristiwa terakhir: selama itu temuan masih menyumbang peluang serangan
AWALAN = "DET-"    # penanda sumber peluang dari mesin deteksi aturan (bandingkan "CTI-…" dan "AI-ANOMALI")

# Daftar jalur OT yang diizinkan (di satuan: ditetapkan pejabat siber satuan). Selain alamat ini, koneksi ke zona kendali = temuan.
JALUR_OT_DIIZINKAN = {"192.0.2.140"}          # stasiun rekayasa OT (RFC 5737)
JENDELA_PEMELIHARAAN = (22, 2)                # perintah tulis hanya wajar pukul 22.00–02.00 waktu setempat
FUNGSI_TULIS_MODBUS = {5, 6, 15, 16}          # write coil/register; fungsi baca (1–4) tidak dihitung
NAMA_FUNGSI_MODBUS = {5: "Write Single Coil", 6: "Write Single Register", 15: "Write Multiple Coils",
                      16: "Write Multiple Registers"}


def dalam_jendela_pemeliharaan(jam: int) -> bool:
    mulai, akhir = JENDELA_PEMELIHARAAN
    return mulai <= jam < akhir if mulai <= akhir else (jam >= mulai or jam < akhir)   # boleh melewati tengah malam


@dataclass
class Temuan:
    id: str
    aturan: str
    sumber: str                 # alamat asal peristiwa (blok dokumentasi RFC 5737 di purwarupa)
    aset: list[str]             # aset yang terkena (id simpul topologi)
    mulai: float                # waktu monotonic peristiwa pertama yang dihitung
    terakhir: float             # waktu monotonic peristiwa terakhir
    jumlah: int                 # banyaknya peristiwa (login gagal / kombinasi alamat:port berbeda)
    rincian: dict = field(default_factory=dict)
    asal: str = "latihan"        # "latihan" (peristiwa sintetis) atau "impor" (log asli dari Operator)
    berkas: str | None = None    # nama berkas log bila asal = "impor"
    sha256_berkas: str | None = None   # v5.4.2: SHA-256 berkas log seperti diterima saat impor
    baris_berkas: int | None = None
    drill: bool = False          # v5.4.2: log cerita sintetis latihan drill (lewat jalur impor, tetapi BUKAN log asli)

    @property
    def nama(self) -> str:
        return ATURAN[self.aturan]["nama"]

    @property
    def keparahan(self) -> str:
        return ATURAN[self.aturan]["keparahan"]

    @property
    def peluang(self) -> float:
        return ATURAN[self.aturan]["peluang"]

    def alasan(self) -> str:
        a = ATURAN[self.aturan]
        durasi = max(1, round(self.terakhir - self.mulai))
        if self.aturan == "login_gagal":
            return (f"{self.jumlah} login gagal dari {self.sumber} dalam {durasi} dtk "
                    f"(ambang {a['ambang']} dalam {a['jendela']} dtk)")
        if self.aturan == "login_tembus":
            return (f"login berhasil dari {self.sumber} setelah {self.rincian.get('gagal', 0)} kali gagal "
                    f"(dalam {a['jendela']} dtk)")
        if self.aturan == "ot_tanpa_izin":
            return (f"{self.sumber} membuka {self.jumlah} koneksi Modbus ke zona kendali; "
                    f"alamat ini tidak ada di daftar jalur OT yang diizinkan")
        if self.aturan == "tulis_ot_luar_jadwal":
            m, s = JENDELA_PEMELIHARAAN
            return (f"{self.jumlah} perintah tulis Modbus (fungsi {self.rincian['fungsi']}) dari {self.sumber} "
                    f"pukul {self.rincian['jam']:02d}.00; jendela pemeliharaan {m:02d}.00–{s:02d}.00")
        if self.aturan == "rantai_it_ot":
            return (f"koneksi tanpa izin ({self.rincian['koneksi']}) disusul perintah tulis "
                    f"({self.rincian['tulis']}) dari {self.sumber} dalam {durasi} dtk")
        return (f"{self.jumlah} kombinasi alamat:port berbeda dari {self.sumber} dalam {durasi} dtk "
                f"(ambang {a['ambang']} dalam {a['jendela']} dtk)")

    def aktif(self, sekarang: float) -> bool:
        return sekarang - self.terakhir <= MASA_AKTIF


class MesinDeteksi:
    """Tanpa jam sendiri: waktu dibawa oleh setiap peristiwa, sehingga uji bisa mengatur waktu dengan tepat."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._gagal: dict[tuple[str, str], deque[float]] = {}
        self._koneksi: dict[str, deque[tuple[float, str, int, str | None]]] = {}
        self._episode: dict[tuple[str, str, str], Temuan] = {}
        self.temuan: list[Temuan] = []
        self._nomor = 0

    def _baru(self, aturan: str, sumber: str, aset: list[str], t0: float, t: float, jumlah: int,
              rincian: dict | None = None) -> Temuan:
        self._nomor += 1
        tm = Temuan(f"{AWALAN}{self._nomor:03d}", aturan, sumber, aset, t0, t, jumlah, rincian or {})
        self.temuan.append(tm)
        del self.temuan[:-50]
        return tm

    def proses(self, peristiwa: dict, t: float) -> list[Temuan]:
        """Satu peristiwa masuk → daftar temuan BARU (kosong bila hanya memperpanjang temuan lama)."""
        if peristiwa["jenis"] == "login":
            return self._login(peristiwa, t)
        if peristiwa["jenis"] == "koneksi":
            return self._koneksi_masuk(peristiwa, t)
        if peristiwa["jenis"] == "koneksi_ot":
            return self._koneksi_ot(peristiwa, t)
        if peristiwa["jenis"] == "modbus":
            return self._modbus(peristiwa, t)
        raise ValueError("Jenis peristiwa tidak dikenal")

    # -- aturan IT/OT -----------------------------------------------------------
    def _perpanjang_atau_baru(self, aturan: str, sumber: str, aset: str, t: float,
                              rincian: dict | None = None) -> tuple[Temuan, bool]:
        """Episode yang masih dalam jendela diperpanjang; selain itu temuan baru. → (temuan, baru?)"""
        ep = self._episode.get((aturan, sumber, aset))
        if ep and t - ep.terakhir <= ATURAN[aturan]["jendela"]:
            ep.terakhir, ep.jumlah = t, ep.jumlah + 1
            return ep, False
        tm = self._baru(aturan, sumber, [aset], t, t, 1, rincian)
        self._episode[(aturan, sumber, aset)] = tm
        return tm, True

    def _koneksi_ot(self, p: dict, t: float) -> list[Temuan]:
        if p["sumber"] in JALUR_OT_DIIZINKAN:
            return []
        tm, baru = self._perpanjang_atau_baru("ot_tanpa_izin", p["sumber"], p["aset"], t)
        return [tm] if baru else []

    def _modbus(self, p: dict, t: float) -> list[Temuan]:
        if p["fungsi"] not in FUNGSI_TULIS_MODBUS or dalam_jendela_pemeliharaan(p["jam"]):
            return []
        sumber, aset = p["sumber"], p["aset"]
        tulis, baru = self._perpanjang_atau_baru("tulis_ot_luar_jadwal", sumber, aset, t,
                                                 {"fungsi": p["fungsi"], "jam": p["jam"]})
        hasil = [tulis] if baru else []
        koneksi = self._episode.get(("ot_tanpa_izin", sumber, aset))
        rantai = self._episode.get(("rantai_it_ot", sumber, aset))
        if koneksi and t - koneksi.terakhir <= ATURAN["rantai_it_ot"]["jendela"]:
            if rantai and rantai.mulai >= koneksi.mulai:          # rantai yang sama: cukup diperpanjang
                rantai.terakhir = t
            else:
                tm = self._baru("rantai_it_ot", sumber, [aset], koneksi.mulai, t, 2,
                                {"koneksi": koneksi.id, "tulis": tulis.id})
                self._episode[("rantai_it_ot", sumber, aset)] = tm
                hasil.append(tm)
        return hasil

    # -- aturan login --------------------------------------------------------
    def _login(self, p: dict, t: float) -> list[Temuan]:
        sumber, aset = p["sumber"], p["aset"]
        kunci = (sumber, aset)
        if p["berhasil"]:
            ep = self._episode.get(("login_gagal", sumber, aset))
            tembus = self._episode.get(("login_tembus", sumber, aset))
            if ep and t - ep.terakhir <= ATURAN["login_tembus"]["jendela"] and not (tembus and tembus.mulai >= ep.mulai):
                tm = self._baru("login_tembus", sumber, [aset], t, t, 1, {"gagal": ep.jumlah, "induk": ep.id})
                self._episode[("login_tembus", sumber, aset)] = tm
                return [tm]
            return []
        a = ATURAN["login_gagal"]
        antre = self._gagal.setdefault(kunci, deque())
        antre.append(t)
        while antre and t - antre[0] > a["jendela"]:
            antre.popleft()
        ep = self._episode.get(("login_gagal", sumber, aset))
        if ep and t - ep.terakhir <= a["jendela"]:          # episode yang sama masih berlangsung
            ep.terakhir, ep.jumlah = t, ep.jumlah + 1
            return []
        if len(antre) >= a["ambang"]:
            tm = self._baru("login_gagal", sumber, [aset], antre[0], t, len(antre))
            self._episode[("login_gagal", sumber, aset)] = tm
            return [tm]
        return []

    # -- aturan pemindaian port ------------------------------------------------
    def _koneksi_masuk(self, p: dict, t: float) -> list[Temuan]:
        sumber, a = p["sumber"], ATURAN["pindai_port"]
        antre = self._koneksi.setdefault(sumber, deque())
        antre.append((t, p["ip"], p["port"], p.get("aset")))
        while antre and t - antre[0][0] > a["jendela"]:
            antre.popleft()
        ep = self._episode.get(("pindai_port", sumber, "*"))
        if ep and t - ep.terakhir <= a["jendela"]:
            ep.terakhir = t
            ep.rincian["kombinasi"].add((p["ip"], p["port"]))
            ep.jumlah = len(ep.rincian["kombinasi"])
            if p.get("aset") and p["aset"] not in ep.aset:
                ep.aset = sorted({*ep.aset, p["aset"]})
                ep.rincian["terbuka"] = ", ".join(ep.aset)
            return []
        kombinasi = {(ip, port) for _, ip, port, _ in antre}
        if len(kombinasi) >= a["ambang"]:
            aset = sorted({x for *_, x in antre if x})
            tm = self._baru("pindai_port", sumber, aset, antre[0][0], t, len(kombinasi),
                            {"kombinasi": kombinasi, "terbuka": ", ".join(aset) or "tidak ada"})
            self._episode[("pindai_port", sumber, "*")] = tm
            return [tm]
        return []

    def aktif(self, sekarang: float) -> list[Temuan]:
        return [tm for tm in self.temuan if tm.aktif(sekarang)]


# -------------------------------------------------------------------------------------------------
# DATA LATIHAN SINTETIS: rangkaian peristiwa mentah untuk tiap latihan (bukan peringatan jadi)
# -------------------------------------------------------------------------------------------------
IP_PENEBAK = "203.0.113.77"     # RFC 5737 TEST-NET-3 (luar gerbang)
IP_PEMINDAI = "198.51.100.66"   # RFC 5737 TEST-NET-2 (luar gerbang)
IP_ADMIN = "192.0.2.150"        # RFC 5737 TEST-NET-1 (stasiun kerja admin internal, login wajar)
IP_REKAYASA_OT = "192.0.2.140"  # stasiun rekayasa OT yang diizinkan (ada di JALUR_OT_DIIZINKAN)
IP_PENYUSUP = "192.0.2.183"     # stasiun kerja kantor yang sudah disusupi (RFC 5737)
PORT_DICOBA = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306,
               3389, 5432, 5900, 6379, 8080, 8443, 502, 873]


def rangkaian_latihan(jenis: str, aset: dict, dmz: list[dict]) -> list[tuple[float, dict]]:
    """[(detik sejak latihan dipicu, peristiwa mentah)]. `aset` = sasaran login; `dmz` = aset yang menghadap internet."""
    if jenis in ("login_gagal", "login_tembus"):
        ev = [(0.5, {"jenis": "login", "sumber": IP_ADMIN, "aset": aset["id"], "berhasil": True})]  # login wajar
        ev += [(1.0 + 2.0 * i, {"jenis": "login", "sumber": IP_PENEBAK, "aset": aset["id"], "berhasil": False})
               for i in range(12)]
        if jenis == "login_tembus":
            ev.append((26.0, {"jenis": "login", "sumber": IP_PENEBAK, "aset": aset["id"], "berhasil": True}))
        return ev
    if jenis == "pindai_port":
        ev, i = [], 0
        for s in dmz:
            for port in PORT_DICOBA:
                ev.append((0.5 + 0.12 * i, {"jenis": "koneksi", "sumber": IP_PEMINDAI, "ip": s["ip"], "port": port,
                                            "aset": s["id"] if port == s["port"] else None}))
                i += 1
        return ev
    if jenis == "akses_ot":
        aid = aset["id"]
        return [  # stasiun rekayasa resmi: tersambung dan MEMBACA register (wajar) → bukan temuan
            (0.5, {"jenis": "koneksi_ot", "sumber": IP_REKAYASA_OT, "aset": aid}),
            (1.0, {"jenis": "modbus", "sumber": IP_REKAYASA_OT, "aset": aid, "fungsi": 3, "jam": 14}),
            # stasiun kerja kantor yang disusupi: menyeberang ke zona kendali, lalu menulis register siang hari
            (3.0, {"jenis": "koneksi_ot", "sumber": IP_PENYUSUP, "aset": aid}),
            *[(6.0 + i, {"jenis": "modbus", "sumber": IP_PENYUSUP, "aset": aid, "fungsi": 16, "jam": 14})
              for i in range(3)],
        ]
    raise ValueError("Jenis latihan deteksi tidak dikenal")


JENIS_LATIHAN = ("login_gagal", "login_tembus", "pindai_port", "akses_ot")
ASET_LATIHAN_OT = "genset"      # latihan akses_ot selalu menyasar pengendali genset (aset OT)
