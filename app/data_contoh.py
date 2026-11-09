# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
data_contoh.py — Semua data di sini SINTETIS (buatan) untuk demo.

Analogi: ini seperti "boneka latihan" di kelas P3K. Bentuknya mirip
aslinya, tetapi tidak ada orang sungguhan yang terlibat.

Prinsip minimisasi data:
- Tidak ada data pribadi warga (nama, NIK, wajah, lokasi).
- Alamat IP memakai blok dokumentasi resmi (RFC 5737) yang memang
  dicadangkan untuk contoh dan TIDAK dipakai di internet nyata.
- Domain memakai akhiran .example / .test (RFC 2606) yang juga khusus contoh.
"""

from __future__ import annotations

import copy

from .istilah import ISTILAH, kepada_manajemen

# --------------------------------------------------------------------------
# 1. ASET SISTEM SATUAN CONTOH — RS dan markas TNI AD (fiktif)
# --------------------------------------------------------------------------
# v5.1: ID lama sengaja dipertahankan agar loket API & uji tetap stabil;
# yang berubah nama aset, cabang pemilik, dan PIC. "sektor" tetap dipakai korelasi CTI.
# "jam sejak backup" & "backup teruji" terinspirasi kasus PDNS 2024 (hanya ~2% data ber-backup).
LAYANAN_AWAL: list[dict] = [
    {"id": "imigrasi", "nama": "Portal Layanan Pasien RSPAD Gatot Soebroto (contoh)", "singkat": "Portal RSPAD",
     "cabang": "RSPAD Gatot Soebroto, Jakarta", "sektor": "Administrasi pemerintahan",
     "jam_sejak_backup": 6, "backup_teruji": True},
    {"id": "perizinan", "nama": "Portal Pemasok Alat Kesehatan Kesdam (contoh)", "singkat": "Portal Alkes Kesdam",
     "cabang": "Kesdam Bandung", "sektor": "Administrasi pemerintahan",
     "jam_sejak_backup": 52, "backup_teruji": True},          # sengaja terlambat → kuning
    {"id": "pajak", "nama": "Sistem Keuangan & Anggaran Markas (contoh)", "singkat": "Keuangan Markas",
     "cabang": "Markas Utama Surabaya", "sektor": "Keuangan",
     "jam_sejak_backup": 12, "backup_teruji": True},
    {"id": "kesehatan", "nama": "RS Kesdam · SIMRS (contoh)", "singkat": "RS Kesdam",
     "cabang": "RS Kesdam Makassar", "sektor": "Kesehatan",
     "jam_sejak_backup": 20, "backup_teruji": False},         # cadangan belum diuji → kuning
    {"id": "listrik", "nama": "Genset & Catu Daya RS Kesdam (contoh)", "singkat": "Genset RS Kesdam",
     "cabang": "RS Kesdam Makassar", "sektor": "Energi",
     "jam_sejak_backup": 8, "backup_teruji": True},
    {"id": "logistik", "nama": "Gudang Logistik Kesehatan Kesdam (contoh)", "singkat": "Gudang Kesdam",
     "cabang": "Gudang Kesdam Pontianak", "sektor": "Logistik",
     "jam_sejak_backup": 10, "backup_teruji": True},
]

# Batas kepatuhan pencadangan (aturan main demo, bisa disesuaikan)
BATAS_JAM_BACKUP = 24

# Dampak operasional (misi) tiap layanan untuk LAPSIT: apa yang terganggu bila layanan berhenti, dan prosedur
# kontinjensinya. PERKIRAAN dampak menurut profil layanan contoh, bukan hasil pengukuran.
DAMPAK_OPERASIONAL: dict[str, dict[str, str]] = {
    "imigrasi": {"misi": "pendaftaran daring dan jadwal kontrol pasien",
                 "kontinjensi": "pendaftaran dilayani di loket"},
    "perizinan": {"misi": "pemesanan dan pengadaan alat kesehatan",
                  "kontinjensi": "pemesanan lewat surat dan telepon resmi"},
    "pajak": {"misi": "pencairan anggaran dan pembayaran satuan",
              "kontinjensi": "pencatatan manual; pembayaran mendesak dengan persetujuan berjenjang"},
    "kesehatan": {"misi": "pendaftaran pasien, rekam medis elektronik, serta layanan laboratorium dan farmasi",
                  "kontinjensi": "rekam medis, resep, dan permintaan laboratorium manual (formulir kertas)"},
    "listrik": {"misi": "catu daya cadangan rumah sakit (IGD, ICU, ruang operasi)",
                "kontinjensi": "genset dikendalikan lokal oleh teknisi di ruang mesin",
                "saat_diisolasi": "jalur kendali jarak jauh diputus; genset TIDAK dimatikan dan tetap siap menyala"},
    "logistik": {"misi": "distribusi obat dan perbekalan kesehatan",
                 "kontinjensi": "kartu stok dan surat jalan manual"},
}
# Gangguan khas tiap skenario terhadap misi layanan ({misi} diisi dari DAMPAK_OPERASIONAL).
GANGGUAN_SKENARIO: dict[str, str] = {
    "ransomware": "berkas terenkripsi; {misi} tidak dapat diakses",
    "backup_dimatikan": "layanan masih berjalan, tetapi cadangan dilepas sehingga {misi} berisiko tidak bisa dipulihkan",
    "ddos": "{misi} melambat hingga tidak dapat diakses dari luar",
    "sabotase_ot": "ada upaya mengubah jadwal start genset; {misi} berisiko terganggu",
}


def salin_layanan_awal() -> dict[str, dict]:
    """Membuat salinan baru data layanan agar data asli tidak ikut berubah."""
    return {l["id"]: copy.deepcopy(l) | {"insiden": None} for l in LAYANAN_AWAL}


# --------------------------------------------------------------------------
# 2. DAFTAR INDIKATOR ANCAMAN CONTOH (IOC = Indicator of Compromise)
# --------------------------------------------------------------------------
# Analogi: daftar "foto buronan" di pos satpam. Bedanya, yang dicari di sini
# adalah ciri mesin (alamat server, nama domain, sidik jari berkas), BUKAN orang.
INDIKATOR_CONTOH: list[dict] = [
    {
        "id": "IOC-001",
        "jenis": "ip",
        "nilai": "203.0.113.45",
        "label": "Server kendali ransomware (contoh)",
        "tingkat": "tinggi",
    },
    {
        "id": "IOC-002",
        "jenis": "ip",
        "nilai": "198.51.100.23",
        "label": "Pemindai port massal (contoh)",
        "tingkat": "sedang",
    },
    {
        "id": "IOC-003",
        "jenis": "domain",
        "nilai": "update-sistem-palsu.example",
        "label": "Domain phishing berkedok pembaruan (contoh)",
        "tingkat": "tinggi",
    },
    {
        "id": "IOC-004",
        "jenis": "domain",
        "nilai": "unduh-backup.test",
        "label": "Domain pengiriman malware (contoh)",
        "tingkat": "sedang",
    },
    {
        # EICAR = berkas uji antivirus resmi yang TIDAK berbahaya.
        # Semua antivirus sengaja mengenalinya, jadi cocok untuk demo.
        "id": "IOC-005",
        "jenis": "hash",
        "nilai": "44d88612fea8a8f36de82e1278abb02f",
        "label": "Berkas uji antivirus EICAR (MD5, tidak berbahaya)",
        "tingkat": "uji",
    },
    {
        "id": "IOC-006",
        "jenis": "hash",
        "nilai": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "label": "Berkas uji antivirus EICAR (SHA-256, tidak berbahaya)",
        "tingkat": "uji",
    },
]

# Indeks pencarian cepat: (jenis, nilai huruf kecil) → indikator
INDEKS_INDIKATOR = {(i["jenis"], i["nilai"].lower()): i for i in INDIKATOR_CONTOH}


# --------------------------------------------------------------------------
# 3. SKENARIO & PLAYBOOK (buku pedoman respons)
# --------------------------------------------------------------------------
# Analogi: prosedur kebakaran yang ditempel di dinding. Saat alarm berbunyi,
# semua orang tahu langkahnya tanpa harus berpikir dari nol.
SKENARIO = {
    "ransomware": "Ransomware mengenkripsi server",
    "backup_dimatikan": "Direktori cadangan tiba-tiba dinonaktifkan",
    "ddos": "Banjir trafik (DDoS) membuat layanan lambat",
    # Fase 6 (IT/OT): penyerang yang sama dengan skenario ransomware berpindah dari jaringan kantor
    # ke zona kendali dan mengirim perintah Modbus asing ke pengendali genset rumah sakit.
    "sabotase_ot": "Perintah Modbus asing ke pengendali genset rumah sakit (OT)",
}

# Log peringatan sintetis yang muncul di pop-up peta saat insiden dipicu.
# Format: (menit relatif terhadap awal insiden, tingkat, pesan).
# Urutan ransomware mengikuti pola umum ransomware (bukan salinan kronologi PDNS):
# tanda bahaya ~2 hari lebih dulu, lalu cadangan dimatikan sesaat sebelum enkripsi.
# (Kronologi PDNS menurut BSSN: upaya mematikan Windows Defender 17 Juni 23.15 WIB,
# aktivitas jahat 20 Juni 00.54.) Alamat IP memakai blok
# dokumentasi dan sengaja cocok dengan daftar indikator contoh, sehingga
# juri bisa langsung mengeceknya di tab "Cek indikator".
LOG_PERINGATAN = {
    "ransomware": [
        (-2880, "sedang", "Login admin dari alamat tak biasa 203.0.113.45 (cocok IOC-001)"),
        (-1440, "sedang", "Akun layanan baru dibuat di luar jam kerja"),
        (-3, "tinggi", "Direktori cadangan dinonaktifkan"),
        (0, "kritis", "Enkripsi massal berkas terdeteksi"),
        (0, "kritis", "Catatan tebusan ditemukan di server"),
    ],
    "backup_dimatikan": [
        (-60, "sedang", "Login admin dari alamat tak biasa 203.0.113.45 (cocok IOC-001)"),
        (0, "tinggi", "Jadwal pencadangan dihentikan oleh akun layanan"),
        (0, "tinggi", "Direktori cadangan dilepas dari server"),
    ],
    "sabotase_ot": [
        (-120, "sedang", "Login jarak jauh ke workstation teknisi fasilitas dari 203.0.113.45 (cocok IOC-001)"),
        (-15, "tinggi", "Kueri Modbus/TCP tak biasa dari jaringan kantor ke pengendali genset 192.0.2.120:502"),
        (0, "kritis", "Perintah tulis Modbus asing: upaya mengubah jadwal start genset"),
    ],
    "ddos": [
        (-10, "sedang", "Lonjakan trafik masuk jauh di atas pola normal"),
        (-5, "tinggi", "Permintaan dari 198.51.100.23 mendominasi (cocok IOC-002)"),
        (0, "kritis", "Waktu respons layanan melewati ambang batas"),
    ],
}

# Teks langkah LAPOR dirakit dari kamus istilah (F-10): ganti istilah, playbook ikut berubah.
_LANGKAH_LAPOR = (f"LAPOR: {ISTILAH['laporan']} ke {kepada_manajemen()} "
                  "(otomatis setelah semua tindakan pemutus selesai)")

PLAYBOOK = {
    "ransomware": [
        "AMANKAN BUKTI: salin memori & log server terdampak, hitung sidik jari SHA-256, catat di buku rantai bukti",
        "ISOLASI: putuskan server terdampak dari jaringan agar tidak menular",
        "LINDUNGI CADANGAN: pastikan salinan cadangan luring tidak tersambung",
        _LANGKAH_LAPOR,
        "JANGAN BAYAR TEBUSAN: jangan berkomunikasi dengan pelaku; serahkan bukti ke tim forensik",
        "PULIHKAN: hidupkan layanan dari cadangan terakhir yang sudah diuji",
        "EVALUASI: catat pelajaran dan perbarui prosedur",
    ],
    "backup_dimatikan": [
        "AMANKAN BUKTI: salin riwayat konfigurasi & jejak login, hitung sidik jari SHA-256, catat di buku rantai bukti",
        "PERIKSA: siapa dan kapan mengubah pengaturan pencadangan",
        "NYALAKAN KEMBALI pencadangan dan buat salinan darurat ke lokasi lain",
        "ISOLASI akun yang mencurigakan (ganti kata sandi, cabut akses)",
        _LANGKAH_LAPOR,
        "PANTAU: awasi tanda-tanda ransomware 48 jam ke depan",
    ],
    "sabotase_ot": [
        "AMANKAN BUKTI: rekam lalu lintas Modbus, log workstation teknisi & konfigurasi pengendali, hitung sidik jari SHA-256, catat di buku rantai bukti",
        "ISOLASI JALUR IT–OT: putus koneksi jaringan kantor ke zona kendali; genset TIDAK dimatikan, beralih ke kendali lokal",
        "BLOKIR akun & akses jarak jauh workstation teknisi, blokir alamat penyerang",
        _LANGKAH_LAPOR,
        "VERIFIKASI FISIK: teknisi memastikan genset & catu daya ruang operasi berjalan normal di lokasi",
        "PULIHKAN jalur kendali setelah konfigurasi pengendali diperiksa dan cocok",
        "EVALUASI: perketat pemisahan zona kendali (NIST SP 800-82)",
    ],
    "ddos": [
        "AMANKAN BUKTI: rekam sampel trafik & log firewall, hitung sidik jari SHA-256, catat di buku rantai bukti",
        "AKTIFKAN perlindungan trafik dari penyedia jaringan",
        "PRIORITASKAN layanan inti, tunda fitur yang tidak penting",
        _LANGKAH_LAPOR,
        "INFORMASIKAN pengguna bahwa layanan sedang ditangani",
        "PULIHKAN kapasitas normal setelah trafik reda",
    ],
}


# v5.1: label 1–2 kata untuk Action Center (teks panjang tetap ada sebagai tooltip).
PLAYBOOK_RINGKAS = {
    "ransomware": [ISTILAH["langkah_bukti"], "Isolasi", "Amankan cadangan", ISTILAH["laporan_singkat"], "Jangan bayar",
                   "Pulihkan", "Evaluasi"],
    "backup_dimatikan": [ISTILAH["langkah_bukti"], "Periksa jejak", "Nyalakan pencadangan", "Cabut akses",
                         ISTILAH["laporan_singkat"], "Pantau 48 jam"],
    "sabotase_ot": [ISTILAH["langkah_bukti"], "Putus IT–OT", "Blokir akses", ISTILAH["laporan_singkat"], "Cek fisik",
                    "Pulihkan jalur", "Evaluasi"],
    "ddos": [ISTILAH["langkah_bukti"], "Saring trafik", "Prioritas inti", ISTILAH["laporan_singkat"], "Info pengguna",
             "Normalkan"],
}
LANGKAH_IR = {s: next(i for i, t in enumerate(PLAYBOOK[s]) if t.startswith("LAPOR")) for s in PLAYBOOK}


# --------------------------------------------------------------------------
# 4. KATALOG BERITA ANCAMAN SINTETIS (Cyber Threat Intelligence / OSINT)
# --------------------------------------------------------------------------
# Analogi: siaran "radio satpam" antar-kompleks perumahan. Isinya kabar umum
# ("ada maling yang sedang mencoba pintu samping rumah-rumah di blok sebelah"),
# BUKAN tentang rumah kita secara khusus. Tugas sistem adalah MENCOCOKKAN kabar
# itu dengan pintu yang benar-benar kita miliki (inventaris aset).
#
# SEMUA FIKTIF: nama sumber, kelompok, dan kampanye dibuat-buat untuk latihan.
# Tidak ada nama lembaga, instansi, atau organisasi sungguhan.
#   port       : layanan jaringan yang disebut dalam berita (kunci korelasi)
#   sektor     : sektor sasaran ("Semua sektor" = tidak spesifik)
#   keyakinan  : seberapa yakin sumber atas laporannya (0..1)
#   ttl        : berapa detik berita dianggap masih segar (dipercepat untuk demo)
#   asal       : wilayah asal kampanye (FIKTIF, hanya untuk animasi Peta Ancaman Global;
#                bukan atribusi pelaku sungguhan)
BERITA_ANCAMAN: list[dict] = [
    {"id": "CTI-101", "asal": "eropa_timur", "sumber": "Pusat Tanggap Siber Fiktif",
     "judul": "Simulasi: eksploitasi layanan berbagi berkas SMBv3 menyasar instansi kesehatan",
     "port": [445], "sektor": "Kesehatan", "keyakinan": 0.80, "ttl": 120,
     "saran": "Batasi port 445 hanya untuk segmen internal dan pasang pembaruan keamanan"},
    {"id": "CTI-102", "asal": "amerika_selatan", "sumber": "Buletin Kerentanan Mingguan (fiktif)",
     "judul": "Simulasi: tebak-sandi massal ke Remote Desktop (RDP) yang terbuka ke internet",
     "port": [3389], "sektor": "Semua sektor", "keyakinan": 0.75, "ttl": 110,
     "saran": "Tutup RDP dari luar; wajibkan VPN dan verifikasi dua langkah"},
    {"id": "CTI-103", "asal": "asia_timur", "sumber": "Forum Berbagi Intelijen Layanan Publik (fiktif)",
     "judul": "Simulasi: celah injeksi pada gateway API port 8080 sedang dieksploitasi aktif",
     "port": [8080], "sektor": "Administrasi pemerintahan", "keyakinan": 0.85, "ttl": 130,
     "saran": "Aktifkan aturan penyaring permintaan API dan perbarui gateway"},
    {"id": "CTI-104", "asal": "eropa_timur", "sumber": "Pusat Tanggap Siber Fiktif",
     "judul": "Simulasi: botnet fiktif 'Gelombang-7' menyiapkan banjir trafik ke portal HTTPS layanan publik",
     "port": [443], "sektor": "Administrasi pemerintahan", "keyakinan": 0.70, "ttl": 120,
     "saran": "Siapkan penyaring trafik dan batas laju di gerbang"},
    {"id": "CTI-105", "asal": "asia_selatan", "sumber": "Laboratorium Riset Keamanan Contoh",
     "judul": "Simulasi: pencurian kredensial SSH lewat kata sandi lemah meningkat",
     "port": [22], "sektor": "Semua sektor", "keyakinan": 0.65, "ttl": 100,
     "saran": "Ganti login sandi dengan kunci SSH dan batasi alamat asal"},
    {"id": "CTI-106", "asal": "eropa_barat", "sumber": "Buletin Kerentanan Mingguan (fiktif)",
     "judul": "Simulasi: kelompok ransomware fiktif mematikan sinkronisasi cadangan (rsync) sebelum mengenkripsi",
     "port": [873], "sektor": "Keuangan", "keyakinan": 0.80, "ttl": 120,
     "saran": "Pastikan salinan cadangan luring dan pantau perubahan jadwal pencadangan"},
    {"id": "CTI-107", "asal": "timur_tengah", "sumber": "Laboratorium Riset Keamanan Contoh",
     "judul": "Simulasi: teknik penyelundupan data lewat kueri DNS (DNS tunneling) terpantau",
     "port": [53], "sektor": "Semua sektor", "keyakinan": 0.55, "ttl": 100,
     "saran": "Pantau kueri DNS yang panjang dan tidak wajar"},
    {"id": "CTI-108", "asal": "amerika_utara", "sumber": "Forum Berbagi Intelijen Layanan Publik (fiktif)",
     "judul": "Simulasi: kerentanan basis data PostgreSQL versi lama dilaporkan",
     "port": [5432], "sektor": "Keuangan", "keyakinan": 0.60, "ttl": 100,
     "saran": "Pastikan basis data tidak terbuka keluar dan versinya mutakhir"},
    {"id": "CTI-109", "asal": "afrika_barat", "sumber": "Pusat Tanggap Siber Fiktif",
     "judul": "Simulasi: celah protokol kendali industri Modbus (port 502) pada gardu listrik",
     "port": [502], "sektor": "Energi", "keyakinan": 0.80, "ttl": 90,
     "saran": "Pisahkan jaringan kendali industri dari jaringan kantor"},
    {"id": "CTI-110", "asal": "asia_tenggara", "sumber": "Buletin Kerentanan Mingguan (fiktif)",
     "judul": "Simulasi: celah gerbang VPN SSL (port 1194) dimanfaatkan untuk masuk jarak jauh",
     "port": [1194], "sektor": "Semua sektor", "keyakinan": 0.70, "ttl": 90,
     "saran": "Perbarui perangkat VPN dan putar ulang kredensial"},
]
INDEKS_BERITA = {b["id"]: b for b in BERITA_ANCAMAN}


# --------------------------------------------------------------------------
# 5. DOKTRIN v5.1 — PRE-AUTHORIZED CONTAINMENT + AUTOMATED IR BLAST
# --------------------------------------------------------------------------
# Analogi: sprinkler gedung. Begitu panas terdeteksi, sprinkler menyala SENDIRI —
# tidak menunggu izin pemilik gedung — dan pada detik yang sama panggilan otomatis
# terkirim ke pemadam. Pemilik gedung DIBERI TAHU, bukan dimintai izin.
#
# Kebijakan ini mengikuti praktik umum incident response: keputusan "boleh mengisolasi"
# disetujui manajemen JAUH HARI (di playbook), bukan saat kebakaran sedang terjadi.
# SEMUA FIKTIF: perusahaan, nama orang, cabang, dan kanal. Tidak ada nomor telepon.
KEBIJAKAN = {
    "kode": "IRP-ISO-01 (simulasi)",
    "isi": f"{ISTILAH['tim_insiden']} jaga berwenang mengisolasi aset yang terkonfirmasi diserang tanpa menunggu "
           f"persetujuan; {ISTILAH['laporan']} terkirim otomatis begitu semua tindakan pemutus selesai.",
}

# MANAJEMEN ATAS: hanya MENERIMA laporan otomatis — tidak ditelepon untuk izin teknis.
MANAJEMEN: list[dict] = ISTILAH["manajemen"]

# Tingkat keparahan laporan per jenis insiden
KEPARAHAN_IR = {"ransomware": "SEV-1", "ddos": "SEV-1", "backup_dimatikan": "SEV-2", "sabotase_ot": "SEV-1"}

# PROFIL ASET: hanya yang dibutuhkan operator saat genting.
#   pic = PIC TEKNIS cabang → ditelepon HANYA untuk koordinasi ("sistem Anda sedang
#         diisolasi, jangan di-restart"), BUKAN untuk meminta izin.
PROFIL_LAYANAN: dict[str, dict] = {
    "imigrasi": {"pic": {"nama": "Bayu Pratama", "jabatan": ISTILAH["pic_cabang_utama"],
                         "cabang": "RSPAD Gatot Soebroto, Jakarta", "kanal": "Jalur Internal SIM-01"}},
    "perizinan": {"pic": {"nama": "Sri Wahyuni", "jabatan": ISTILAH["pic_cabang"],
                          "cabang": "Kesdam Bandung", "kanal": "Jalur Internal SIM-11"}},
    "pajak": {"pic": {"nama": "Dewi Lestari", "jabatan": ISTILAH["pic_basis_data"],
                      "cabang": "Markas Utama Surabaya", "kanal": "Jalur Internal SIM-21"}},
    "kesehatan": {"pic": {"nama": "Fajar Nugroho", "jabatan": ISTILAH["pic_cabang"],
                          "cabang": "RS Kesdam Makassar", "kanal": "Jalur Internal SIM-31"}},
    "listrik": {"pic": {"nama": "Rizky Ramadhan", "jabatan": ISTILAH["pic_cabang"],
                        "cabang": "RS Kesdam Makassar", "kanal": "Jalur Internal SIM-41"}},
    "logistik": {"pic": {"nama": "Lestari Handayani", "jabatan": ISTILAH["pic_basis_data"],
                         "cabang": "Gudang Kesdam Pontianak", "kanal": "Jalur Internal SIM-51"}},
}
