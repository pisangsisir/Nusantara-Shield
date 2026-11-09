"""Pengaturan bersama untuk semua uji: sandi uji dipasang SEBELUM aplikasi dimuat."""
import os

import pytest

os.environ["NS_OPERATOR_PASSWORD"] = "sandi-operator-uji-123"
os.environ["NS_VIEWER_PASSWORD"] = "sandi-pengamat-uji-123"
os.environ.pop("NS_AUDIT_KEY", None)  # log audit di memori saja selama uji
for _env in ("NS_AKUN_FILE", "NS_KODE_OPERATOR"):
    os.environ.pop(_env, None)       # akun terdaftar di memori saja; pendaftaran operator tertutup

# Fase 5 (audit #6): judul kelompok uji dicetak setiap kali pytest pindah ke berkas uji berikutnya,
# supaya terminal menjelaskan BAGIAN APA dari sistem yang sedang diperiksa.
KELOMPOK = {
    "test_keamanan.py": "Keamanan & akses: login, peran, batas laju, header, batas ukuran kiriman, log audit",
    "test_akun.py": "Manajemen akun: pendaftaran pengamat/operator, dasbor akun operator",
    "test_telemetri.py": "Telemetri & siaran: panel bergerak, dapur tunggal, tambalan delta",
    "test_cti_soar.py": "Intelijen ancaman (CTI) & SOAR: prediksi, pengerasan, isolasi, peta",
    "test_komando.py": "Rantai komando & laporan: isolasi pre-authorized, LAPSIT, Quick Call",
    "test_rantai_bukti.py": "Rantai bukti forensik: bukti sebelum isolasi, isolasi darurat, cocok hash",
    "test_istilah.py": "Kamus istilah: tidak ada label yang tertanam di luar app/istilah.py",
    "test_ot.py": "Sinergi IT/OT: kabar Modbus menaikkan pengendali genset ke WASPADA",
    "test_ai.py": "AI lokal: deteksi anomali Isolation Forest, luring, dengan alasan yang bisa dibaca",
    "test_paket_luring.py": "Paket pasang luring: sidik jari SHA-256, pemasangan tanpa internet",
    "test_triase_kesiapan.py": "Triase & Kesiapan Siber: penutupan peringatan beralasan, nilai A–E terbuka",
    "test_deteksi.py": "Mesin Deteksi Aturan: login gagal berulang, login tembus, pemindaian port (ambang terbuka)",
    "test_linimasa.py": "Linimasa 60 menit (data latihan), pita anomali AI per aset, KPI MTTC dan insiden",
    "test_impor_log.py": "Impor log luring: auth.log OpenSSH, firewall UFW/iptables, CSV; aturan sama, dua kunci utuh",
    "test_ot_mitre_lapsit.py": "Aturan OT, label MITRE ATT&CK, label sumber data, dan pengesahan dua tanda tangan LAPSIT",
    "test_verifikasi_audit.py": "Verifikasi audit tanpa server: CLI mandiri menghitung ulang rantai HMAC log audit dan buku bukti",
    "test_paket_ubuntu.py": "Paket pasang Ubuntu 24.04: tanda tangan Ed25519, manifest SHA-256, pemasang menolak paket yang diubah",
    "test_versi.py": "Satu sumber versi: dasbor, LAPSIT, dan paket memakai app/versi.py; nama peran berhuruf kapital",
    "test_titik_periksa.py": "Titik periksa Ed25519: kunci berevolusi, auditor memeriksa dengan kunci publik saja",
}
_berkas_terakhir = {"nama": None}
_CONFIG = {"config": None}


def pytest_configure(config):
    _CONFIG["config"] = config


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_logstart(nodeid, location):
    berkas = os.path.basename(location[0])
    if berkas == _berkas_terakhir["nama"]:
        return
    _berkas_terakhir["nama"] = berkas
    tr = _CONFIG["config"].pluginmanager.get_plugin("terminalreporter") if _CONFIG["config"] else None
    if tr and tr.verbosity >= 1:
        tr.ensure_newline()
        tr.write_line("")
        tr.write_sep("─", f"▶ {KELOMPOK.get(berkas, berkas)}", cyan=True, bold=True)



# Tinjauan ahli (9 Nov 2026): jumlah uji bukan ukuran mutu, jadi ringkasan akhir mengelompokkan uji yang LULUS
# per aturan doktrin yang dijaganya. Pemetaan per berkas uji (satu berkas = satu aturan utama); uji pendukung
# (kamus istilah, versi, telemetri) dipisah supaya tidak menggelembungkan angka doktrin.
DOKTRIN = [
    ("Tangkal lebih dulu: peringatan dini beralasan", ["test_ai.py", "test_deteksi.py", "test_ot.py", "test_cti_soar.py",
                                                       "test_triase_kesiapan.py", "test_impor_log.py", "test_ot_mitre_lapsit.py"]),
    ("Manusia memutuskan: peran, tombol ditahan, mesin tidak mengeksekusi", ["test_keamanan.py", "test_akun.py", "test_komando.py"]),
    ("Bukti dulu, baru putus: tanpa bukti ditolak sistem", ["test_rantai_bukti.py"]),
    ("Jejak tidak bisa ditulis ulang: HMAC + titik periksa Ed25519", ["test_verifikasi_audit.py", "test_titik_periksa.py"]),
    ("Luring dan paket tepercaya: sidik jari, tanda tangan", ["test_paket_luring.py", "test_paket_ubuntu.py"]),
    ("Pendukung (bukan doktrin): istilah, versi, siaran, linimasa", ["test_istilah.py", "test_versi.py", "test_telemetri.py",
                                                                     "test_linimasa.py"]),
]


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    lulus: dict[str, int] = {}
    for laporan in terminalreporter.stats.get("passed", []):
        berkas = os.path.basename(laporan.nodeid.split("::")[0])
        lulus[berkas] = lulus.get(berkas, 0) + 1
    if not lulus:
        return
    terpetakan = {b for _, daftar in DOKTRIN for b in daftar}
    terminalreporter.write_sep("─", "Uji LULUS per aturan doktrin", cyan=True, bold=True)
    for aturan, daftar in DOKTRIN:
        n = sum(lulus.get(b, 0) for b in daftar)
        if n:
            terminalreporter.write_line(f"  {n:>4}  {aturan}")
    lain = sum(n for b, n in lulus.items() if b not in terpetakan)
    if lain:
        terminalreporter.write_line(f"  {lain:>4}  BELUM DIPETAKAN ke aturan doktrin (perbarui DOKTRIN di tests/conftest.py)")
