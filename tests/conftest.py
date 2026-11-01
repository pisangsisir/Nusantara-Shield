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

