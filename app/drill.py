# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
drill.py — Drill kesiapan: latihan tanggap insiden (cyber drill) untuk Operator yang bukan ahli siber.

Analogi: latihan pemadam kebakaran. Gedungnya tidak dibakar; yang dilatih adalah urutan tindakan petugas, dan
stopwatch pelatih mencatat berapa lama sampai selang terpasang. Di sini "asap" adalah log sintetis satu cerita,
"selang" adalah tombol di Action Center, dan "stopwatch" adalah jejak yang memang sudah dicatat sistem (MTTC,
buku rantai bukti, isolasi darurat). Nilai tidak berasal dari pengakuan Operator.

Dasar kebutuhan: Perpres 82/2022 Pasal 4 memasukkan sektor kesehatan dan pertahanan sebagai Infrastruktur Informasi
Vital; Pasal 15 mewajibkan Penyelenggara IIV melaksanakan simulasi tanggap Insiden Siber. Narasumber Satsiber dan
webinar pembekalan lomba sama-sama menyebut masalah terbesarnya: SDM siber spesialis langka.

Alur satu drill:
  1. Log cerita sintetis (auth.log, alamat RFC 5737) dimasukkan lewat jalur impor log yang SAMA dengan log asli.
     Mesin deteksi aturan menilainya; drill hanya mencocokkan aturan yang seharusnya menangkap cerita itu
     (kunci jawaban deteksi). Aturan yang diam ikut dilaporkan: drill juga menguji aturan deteksi.
  2. Insiden latihan dimulai di layanan sasaran. Operator merespons dari Action Center seperti insiden biasa.
  3. Empat pertanyaan, satu per fase penanganan insiden (NIST SP 800-61: deteksi dan analisis; penahanan,
     pembersihan, dan pemulihan). Kunci jawaban tidak dikirim ke browser sebelum pertanyaan dijawab.
  4. Nilai kesiapan 0–100 dengan rumus terbuka (BOBOT, AMBANG_KECEPATAN di bawah). Setiap komponen menyebut sumber
     angkanya. Hasil masuk log audit berantai dan LAPSIT, ditandai LATIHAN.

Batas yang jujur:
  - Dua skenario: cadangan dilepas (auth.log, pola awal kasus PDNS) dan perintah asing ke pengendali genset
    (Suricata eve.json). Skenario perubahan halaman situs satuan dan tabletop exercise untuk pimpinan belum dibangun.
  - Ambang kecepatan adalah target latihan purwarupa, bukan standar resmi; satuan dapat menyesuaikannya.
  - Drill mengukur keputusan dan kecepatan di purwarupa ini, bukan kemampuan forensik Operator.
"""

from __future__ import annotations

import json
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone

from .deteksi import ATURAN
from .istilah import ISTILAH
from .lapsit import zona
from .telemetri import huruf_nilai

PENYERANG = "203.0.113.45"     # sama dengan IOC-001 di data contoh (RFC 5737)
HOST = "simrs-adm"
MAKS_RIWAYAT = 5

# Rumus nilai terbuka: kunci → (label, bobot). Jumlah bobot = 100.
BOBOT: dict[str, tuple[str, int]] = {
    "ketepatan": ("Ketepatan keputusan", 40),     # 10 per pertanyaan fase IR yang dijawab benar
    "bukti": ("Bukti sebelum putus", 30),         # bukti diamankan sebelum jaringan diputus
    "kecepatan": ("Kecepatan penahanan", 30),     # MTTC: sejak insiden latihan dimulai sampai jalur penyerang putus
}
NILAI_PER_JAWABAN = 10
# Target latihan purwarupa (bukan standar resmi): MTTC paling lama (detik) → nilai.
AMBANG_KECEPATAN = ((180, 30), (420, 20), (900, 10))
NILAI_BUKTI_SUSULAN = 15


class GalatDrill(ValueError):
    """Permintaan tidak sah untuk keadaan drill saat ini (dijawab 409 oleh loket)."""


# ---------------------------------------------------------------- katalog skenario
# Detik relatif cerita: (detik, isi baris setelah nama host). Baris sudo dan sesi tidak dikenali pembaca impor
# (dihitung "diabaikan"), sama seperti log asli: yang dinilai aturan hanya upaya login.
_CERITA_CADANGAN = (
    [(4 * i, f"sshd[2114]: Failed password for admin from {PENYERANG} port {50100 + i} ssh2") for i in range(10)]
    + [
        (44, f"sshd[2131]: Accepted password for svc_backup from {PENYERANG} port 51234 ssh2"),
        (44, "sshd[2131]: pam_unix(sshd:session): session opened for user svc_backup(uid=1003)"),
        (95, "sudo: svc_backup : TTY=pts/0 ; PWD=/home/svc_backup ; USER=root ; "
             "COMMAND=/usr/bin/systemctl stop cadangan-harian.timer"),
        (110, "sudo: svc_backup : TTY=pts/0 ; PWD=/home/svc_backup ; USER=root ; "
              "COMMAND=/usr/bin/systemctl disable cadangan-harian.timer"),
        (140, "sudo: svc_backup : TTY=pts/0 ; PWD=/home/svc_backup ; USER=root ; COMMAND=/usr/bin/umount /srv/cadangan"),
        (170, "sudo: svc_backup : TTY=pts/0 ; PWD=/home/svc_backup ; USER=root ; "
              "COMMAND=/usr/bin/truncate -s 0 /home/svc_backup/.bash_history"),
        (185, f"sshd[2131]: Disconnected from user svc_backup {PENYERANG} port 51234"),
    ]
)

# Cerita OT dalam format Suricata eve.json (sensor yang mungkin sudah dimiliki satuan). (detik, objek tanpa timestamp).
# HMI resmi 192.0.2.140 membaca register (bukan temuan); stasiun kerja kantor 192.0.2.183 menyeberang ke zona kendali,
# membaca, lalu menulis register jadwal start genset. Dinilai mesin deteksi aturan lewat jalur impor yang sama.
HMI, PENYUSUP_OT, GENSET = "192.0.2.140", "192.0.2.183", "192.0.2.120"


def _aliran(src: str, sport: int) -> dict:
    return {"event_type": "flow", "src_ip": src, "src_port": sport, "dest_ip": GENSET, "dest_port": 502, "proto": "TCP",
            "app_proto": "modbus"}


def _modbus(src: str, sport: int, fungsi: int, nama: str) -> dict:
    return {"event_type": "modbus", "src_ip": src, "src_port": sport, "dest_ip": GENSET, "dest_port": 502, "proto": "TCP",
            "modbus": {"request": {"unit_id": 1, "function_raw": fungsi, "function_code": nama}}}


_CERITA_OT = [
    (0, _aliran(HMI, 50200)), (1, _modbus(HMI, 50200, 3, "ReadHoldingRegisters")),
    (30, _aliran(PENYUSUP_OT, 50310)), (32, _modbus(PENYUSUP_OT, 50310, 3, "ReadHoldingRegisters")),
    (35, _modbus(PENYUSUP_OT, 50310, 6, "WriteSingleRegister")),
    (37, _modbus(PENYUSUP_OT, 50310, 16, "WriteMultipleRegisters")),
    (40, {"event_type": "stats", "stats": {"uptime": 3600}}),
]


def _soal_cadangan(j: dict[int, str]) -> list[dict]:
    return [
        {"fase": "Deteksi", "teks": "Pukul berapa penyerang PERTAMA KALI berhasil masuk menurut log?",
         "opsi": {"a": f"{j[0]} (login gagal pertama)", "b": f"{j[140]} (direktori cadangan dilepas)",
                  "c": f"{j[44]} (login diterima)", "d": f"{j[95]} (jadwal cadangan dihentikan)"},
         "kunci": "c",
         "penjelasan": "Baris «Accepted password» adalah login yang berhasil. Sepuluh baris «Failed password» "
                       f"sebelumnya adalah tebakan sandi yang gagal; {ISTILAH['mesin_aturan']} menandainya sebagai login "
                       "gagal berulang, lalu login tembus. Jam inilah awal kendali penyerang."},
        {"fase": "Analisis", "teks": "Akun mana yang dipakai penyerang untuk masuk dan mematikan cadangan?",
         "opsi": {"a": "admin", "b": "svc_backup", "c": "root", "d": "operator"},
         "kunci": "b",
         "penjelasan": "Tebakan sandi ke akun admin gagal semua; yang diterima adalah akun layanan svc_backup, lalu "
                       "akun itu memakai sudo untuk menghentikan jadwal cadangan dan melepas direktori cadangan. "
                       "Akun layanan bersandi lemah adalah pintu masuk yang sering terlupa."},
        {"fase": "Penahanan", "teks": "Apa langkah pertama yang paling tepat sekarang?",
         "opsi": {"a": "Putus jaringan server secepatnya; bukti bisa diambil nanti.",
                  "b": "Pulihkan cadangan dari salinan lain supaya data aman.",
                  "c": "Tunggu sampai ada berkas terenkripsi agar yakin ini serangan.",
                  "d": "Segel bukti dulu (jejak login dan riwayat konfigurasi), lalu cabut akses svc_backup dan blokir "
                       f"{PENYERANG}."},
         "kunci": "d",
         "penjelasan": "Bukti dulu, baru putus. Memutus tanpa bukti atau memulihkan lebih dulu menghapus jejak "
                       "penyerang. Menunggu enkripsi mengulang pelajaran PDNS: tanda bahaya sudah ada, tindakannya "
                       "terlambat. Di Action Center, tombol isolasi mengamankan bukti otomatis sebelum memutus."},
        {"fase": "Pemulihan", "teks": "Kapan pencadangan boleh dinyalakan ulang dan layanan dinyatakan pulih?",
         "opsi": {"a": "Setelah sidik jari bukti dicocokkan ulang dengan berita acara, akses penyerang dicabut, dan "
                       "cadangan baru diuji pulih.",
                  "b": "Segera setelah akun svc_backup diblokir.",
                  "c": "Setelah server di-restart.",
                  "d": "Setelah laporan ke pimpinan terkirim."},
         "kunci": "a",
         "penjelasan": "Pemulihan menimpa keadaan server, jadi bukti harus sudah tersegel dan cocok. Cadangan yang "
                       "belum pernah diuji pulih ibarat payung yang belum pernah dibuka. Restart atau laporan tidak "
                       "menutup celah yang dipakai penyerang."},
    ]


def _soal_ot(j: dict[int, str]) -> list[dict]:
    return [
        {"fase": "Deteksi", "teks": "Pukul berapa perintah TULIS pertama yang tidak sah sampai ke pengendali genset?",
         "opsi": {"a": f"{j[1]} (HMI resmi membaca register)", "b": f"{j[30]} (koneksi dari jaringan kantor dibuka)",
                  "c": f"{j[32]} (register dibaca dari jaringan kantor)", "d": f"{j[35]} (WriteSingleRegister)"},
         "kunci": "d",
         "penjelasan": "Fungsi Modbus 6 (WriteSingleRegister) dan 16 (WriteMultipleRegisters) mengubah isi register; "
                       "fungsi 3 hanya membaca. Perintah tulis pertama dari stasiun kerja kantor adalah saat jadwal "
                       "genset mulai diubah."},
        {"fase": "Analisis", "teks": f"Mengapa {PENYUSUP_OT} dianggap tidak sah, sedangkan {HMI} tidak?",
         "opsi": {"a": f"{PENYUSUP_OT} memakai port yang berbeda.",
                  "b": f"{HMI} hanya membaca, jadi alamat apa pun yang membaca pasti aman.",
                  "c": f"{HMI} adalah stasiun rekayasa (HMI) yang terdaftar; {PENYUSUP_OT} tidak ada di daftar jalur OT "
                       "dan menulis register di luar jendela pemeliharaan 22.00–02.00.",
                  "d": "Pengendali genset menolak perintah dari alamat itu."},
         "kunci": "c",
         "penjelasan": "Zona kendali dijaga dengan daftar jalur yang diizinkan dan jendela pemeliharaan. Koneksi dari "
                       "alamat di luar daftar, disusul perintah tulis di luar jendela, membentuk rantai IT ke OT: tanda "
                       "penyerang sudah menyeberang dari jaringan kantor."},
        {"fase": "Penahanan", "teks": "Apa langkah pertama yang paling tepat sekarang?",
         "opsi": {"a": "Matikan genset supaya perintah asing tidak berpengaruh.",
                  "b": "Segel bukti (rekaman Modbus, log stasiun kerja, konfigurasi pengendali), lalu putus jalur kantor "
                       "ke zona kendali. Genset tetap menyala dengan kendali lokal.",
                  "c": "Blokir semua lalu lintas Modbus, termasuk dari HMI resmi.",
                  "d": "Tunggu sampai jadwal start genset benar-benar berubah agar yakin."},
         "kunci": "b",
         "penjelasan": "Di rumah sakit, genset adalah cadangan daya IGD, ICU, dan ruang operasi; mematikannya justru "
                       "menyelesaikan pekerjaan penyerang. Yang diputus adalah jalur antara jaringan kantor dan zona "
                       "kendali (NIST SP 800-82), setelah bukti tersegel. Memblokir HMI resmi membutakan teknisi sendiri."},
        {"fase": "Pemulihan", "teks": "Kapan jalur kendali jarak jauh boleh disambung lagi?",
         "opsi": {"a": "Setelah stasiun kerja kantor di-restart.",
                  "b": "Segera setelah laporan ke pimpinan terkirim.",
                  "c": "Setelah satu jam tanpa peringatan baru.",
                  "d": "Setelah konfigurasi dan jadwal start genset dicek fisik, akses jarak jauh stasiun kerja dicabut, "
                       "dan sidik jari bukti dicocokkan ulang dengan berita acara."},
         "kunci": "d",
         "penjelasan": "Penyerang sempat menulis register, jadi isi pengendali harus dicek langsung di ruang mesin, "
                       "bukan dari layar yang mungkin sudah dimanipulasi. Restart, laporan, atau sepinya peringatan "
                       "tidak membuktikan celahnya tertutup."},
    ]


KATALOG: dict[str, dict] = {
    "cadangan_dilepas": {
        "judul": "Cadangan dilepas sebelum serangan",
        "ringkas": "Akun layanan cadangan dibobol lewat tebakan sandi, lalu jadwal pencadangan dimatikan dan "
                   "direktori cadangan dilepas. Pola awal kasus PDNS 2024: tanda bahaya ada sebelum enkripsi.",
        "layanan_id": "kesehatan",
        "skenario": "backup_dimatikan",
        "aset_ssh": "ssh",
        "format": "auth.log",
        "aturan_harus": ["login_gagal", "login_tembus"],
        "cerita": _CERITA_CADANGAN,
        "soal": _soal_cadangan,
        "jam_tetap": None,
    },
    "genset_dari_kantor": {
        "judul": "Perintah asing ke pengendali genset",
        "ringkas": "Stasiun kerja kantor menyeberang ke zona kendali OT lalu menulis register jadwal start genset "
                   "rumah sakit. Log dari sensor jaringan Suricata (eve.json), format yang sudah dipakai banyak SOC.",
        "layanan_id": "listrik",
        "skenario": "sabotase_ot",
        "aset_ssh": "ssh",
        "format": "Suricata eve.json",
        "aturan_harus": ["ot_tanpa_izin", "tulis_ot_luar_jadwal", "rantai_it_ot"],
        "cerita": _CERITA_OT,
        "soal": _soal_ot,
        # Perintah tulis wajar di jendela pemeliharaan 22.00–02.00. Supaya cerita selalu "di luar jendela", ia
        # ditaruh pada pukul 14.00 terakhir yang sudah lewat (zona waktu satuan), bukan pada jam drill dibuka.
        "jam_tetap": 14,
    },
}


def _iso_lokal(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, zona()[1]).isoformat(timespec="seconds")


def _jam(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, zona()[1]).strftime("%H:%M:%S")


def awal_cerita(kode: str, sekarang: float) -> float:
    """Epoch detik ke-0 cerita: ≈4 menit sebelum drill, atau pukul `jam_tetap` terakhir yang sudah lewat."""
    jam = KATALOG[kode]["jam_tetap"]
    if jam is None:
        return sekarang - 240
    kini = datetime.fromtimestamp(sekarang, zona()[1])
    titik = kini.replace(hour=jam, minute=0, second=0, microsecond=0)
    if titik.timestamp() > sekarang - 120:
        titik -= timedelta(days=1)
    return titik.timestamp()


def log_cerita(kode: str, awal: float) -> str:
    """Teks log sintetis satu cerita; detik ke-0 = epoch `awal`, ditulis dalam zona waktu satuan (NS_ZONA_WAKTU)."""
    k, nama_zona = KATALOG[kode], zona()[0]
    tanda = (f"SIMULASI drill kesiapan «{k['judul']}». Data sintetis, alamat RFC 5737, zona waktu {nama_zona}.")
    if k["format"] == "auth.log":
        baris = [f"# {tanda}"] + [f"{_iso_lokal(awal + dt)} {HOST} {isi}" for dt, isi in k["cerita"]]
    else:   # JSON per baris ala eve.json; stempel waktu bergaya Suricata (+0700). Penanda simulasi = event "stats".
        def stempel(t: float) -> str:
            return datetime.fromtimestamp(t, zona()[1]).strftime("%Y-%m-%dT%H:%M:%S.000%z")
        baris = [json.dumps({"timestamp": stempel(awal - 1), "event_type": "stats", "catatan": tanda}, ensure_ascii=False)]
        baris += [json.dumps({"timestamp": stempel(awal + dt), **o}, ensure_ascii=False) for dt, o in k["cerita"]]
    return "\n".join(baris) + "\n"


def _pertanyaan(kode: str, awal: float) -> list[dict]:
    """Empat pertanyaan per fase IR. Jam di pertanyaan diambil dari log cerita yang sama."""
    k = KATALOG[kode]
    return k["soal"]({dt: _jam(awal + dt) for dt, _ in k["cerita"]})


# ---------------------------------------------------------------- rumus nilai (terbuka)
def nilai_kecepatan(mttc_detik: int | None) -> int:
    if mttc_detik is None:
        return 0
    return next((n for batas, n in AMBANG_KECEPATAN if mttc_detik <= batas), 0)


def _komponen_bukti(r: dict) -> tuple[int, str]:
    bukti, darurat = r.get("bukti_detik"), r.get("darurat_detik")
    if darurat is not None and bukti is not None:
        return NILAI_BUKTI_SUSULAN, (f"Isolasi darurat T+{darurat} dtk, bukti {r.get('bukti_nomor')} diamankan "
                                     f"susulan T+{bukti} dtk")
    if darurat is not None:
        return 0, f"Isolasi darurat T+{darurat} dtk tanpa bukti: jejak penyerang berisiko hilang"
    if bukti is not None:
        return BOBOT["bukti"][1], f"Bukti {r.get('bukti_nomor')} diamankan T+{bukti} dtk, sebelum jaringan diputus"
    return 0, "Bukti belum diamankan dan jaringan belum diputus"


def nilai_drill(pertanyaan: list[dict], respons: dict) -> list[dict]:
    """→ komponen nilai: [{kunci, label, nilai, maks, sumber, rincian}]. respons = Menara.respons(...)."""
    benar = sum(1 for p in pertanyaan if p.get("benar"))
    nb, rb = _komponen_bukti(respons)
    mttc = respons.get("mttc_detik")
    target = ", ".join(f"≤{b} dtk = {n}" for b, n in AMBANG_KECEPATAN)
    rk = (f"MTTC {mttc} dtk (target latihan: {target})" if mttc is not None
          else "Insiden belum ditahan saat drill diakhiri")
    return [
        {"kunci": "ketepatan", "label": BOBOT["ketepatan"][0], "nilai": benar * NILAI_PER_JAWABAN,
         "maks": BOBOT["ketepatan"][1], "sumber": f"Jawaban {len(pertanyaan)} pertanyaan fase IR",
         "rincian": f"{benar} dari {len(pertanyaan)} benar"},
        {"kunci": "bukti", "label": BOBOT["bukti"][0], "nilai": nb, "maks": BOBOT["bukti"][1],
         "sumber": ISTILAH["buku_bukti"], "rincian": rb},
        {"kunci": "kecepatan", "label": BOBOT["kecepatan"][0], "nilai": nilai_kecepatan(mttc),
         "maks": BOBOT["kecepatan"][1], "sumber": "MTTC (waktu penahanan tercatat sistem)", "rincian": rk},
    ]


# ---------------------------------------------------------------- pengelola state
def _iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class PengelolaDrill:
    """Satu drill aktif per posko; riwayat beberapa hasil terakhir untuk dasbor dan LAPSIT."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.aktif: dict | None = None
        self.riwayat: deque[dict] = deque(maxlen=MAKS_RIWAYAT)

    def katalog(self) -> list[dict]:
        return [{"kode": k, "judul": v["judul"], "ringkas": v["ringkas"], "layanan_id": v["layanan_id"],
                 "format": v["format"]} for k, v in KATALOG.items()]

    def mulai(self, kode: str, oleh: str, log: str, awal: float, impor: dict) -> dict:
        if self.aktif:
            raise GalatDrill(f"Drill {self.aktif['id']} masih berjalan: selesaikan dulu")
        k = KATALOG[kode]
        muncul = {t["aturan"] for t in impor.get("temuan", [])}
        self.aktif = {
            "id": f"DRL-{uuid.uuid4().hex[:6].upper()}", "kode": kode, "judul": k["judul"], "ringkas": k["ringkas"],
            "layanan_id": k["layanan_id"], "mulai": _iso(), "oleh": oleh, "log": log, "format": k["format"],
            "impor": {x: impor[x] for x in ("format", "baris", "dikenali", "diabaikan")},
            "deteksi": [{"aturan": a, "nama": ATURAN[a]["nama"], "muncul": a in muncul} for a in k["aturan_harus"]],
            "pertanyaan": [{**p, "dijawab": None, "benar": None} for p in _pertanyaan(kode, awal)],
        }
        return self.tampil()

    def jawab(self, no: int, pilihan: str) -> dict:
        if not self.aktif:
            raise GalatDrill("Tidak ada drill yang sedang berjalan")
        p = self.aktif["pertanyaan"][no]
        if p["dijawab"] is not None:
            raise GalatDrill("Pertanyaan ini sudah dijawab; jawaban tidak bisa diubah")
        p["dijawab"], p["benar"] = pilihan, pilihan == p["kunci"]
        return {"no": no, "fase": p["fase"], "benar": p["benar"], "kunci": p["kunci"], "penjelasan": p["penjelasan"]}

    def selesai(self, respons: dict, oleh: str) -> dict:
        if not self.aktif:
            raise GalatDrill("Tidak ada drill yang sedang berjalan")
        a = self.aktif
        komponen = nilai_drill(a["pertanyaan"], respons)
        nilai = sum(x["nilai"] for x in komponen)
        diam = [d["nama"] for d in a["deteksi"] if not d["muncul"]]
        hasil = {
            "id": a["id"], "kode": a["kode"], "judul": a["judul"], "layanan_id": a["layanan_id"], "mulai": a["mulai"],
            "selesai": _iso(), "oleh": oleh, "nilai": nilai, "huruf": huruf_nilai(nilai), "komponen": komponen,
            "benar": sum(1 for p in a["pertanyaan"] if p["benar"]), "jumlah_pertanyaan": len(a["pertanyaan"]),
            "mttc_detik": respons.get("mttc_detik"), "darurat": respons.get("darurat_detik") is not None,
            "deteksi": a["deteksi"], "deteksi_lengkap": not diam,
            "catatan_deteksi": ("Semua aturan yang seharusnya menangkap cerita ini memang muncul." if not diam else
                                f"Aturan tidak menangkap cerita ini: {', '.join(diam)}. Periksa ambang di "
                                "app/deteksi.py sebelum dipakai pada log asli."),
        }
        self.riwayat.appendleft(hasil)
        self.aktif = None
        return hasil

    def batal(self) -> str | None:
        drill_id = self.aktif["id"] if self.aktif else None
        self.aktif = None
        return drill_id

    def tampil(self) -> dict | None:
        """Untuk browser: kunci dan penjelasan hanya untuk pertanyaan yang sudah dijawab."""
        if not self.aktif:
            return None
        a = self.aktif
        soal = []
        for p in a["pertanyaan"]:
            x = {"fase": p["fase"], "teks": p["teks"], "opsi": p["opsi"]}
            if p["dijawab"] is not None:
                x |= {"dijawab": p["dijawab"], "benar": p["benar"], "kunci": p["kunci"], "penjelasan": p["penjelasan"]}
            soal.append(x)
        return {**{k: v for k, v in a.items() if k != "pertanyaan"}, "pertanyaan": soal,
                "terjawab": sum(1 for p in a["pertanyaan"] if p["dijawab"] is not None)}


DRILL = PengelolaDrill()
