# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
bukti.py — Rantai bukti forensik (chain of custody), Fase 4.

Analogi olah TKP: sebelum garis polisi dipasang dan sebelum TKP dibersihkan, petugas
(1) memotret dan mengantongi barang bukti, (2) menyegel kantongnya dengan nomor segel, dan
(3) mencatat di BERITA ACARA siapa yang mengambil, kapan, dan nomor segelnya.
Di sistem ini:
  - "kantong bukti"  = salinan berkas di BRANKAS (simulasi: isi acak, tidak ada data sungguhan);
  - "nomor segel"    = sidik jari SHA-256 tiap berkas + sidik jari gabungan (manifest);
  - "berita acara"   = BUKU RANTAI BUKTI: buku tambah-saja yang tiap halamannya memuat sidik jari
                       HMAC halaman sebelumnya (kelas yang sama dengan log audit).
Sebelum layanan dipulihkan (yang akan MENGHAPUS jejak penyerang), isi brankas dihitung ulang
sidik jarinya dan dicocokkan dengan berita acara. Tidak cocok = pemulihan dikunci.

SIMULASI: tidak ada memori atau log sungguhan yang disalin. Isi "berkas" dibangkitkan acak agar
sidik jarinya unik dan bisa diverifikasi; ukuran berkas hanya label.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from .audit import LogAudit
from .penomoran import PencacahIR

# Barang bukti per skenario: (nama berkas, keterangan, ukuran tampilan). Semua SIMULASI.
ARTEFAK: dict[str, list[tuple[str, str, str]]] = {
    "ransomware": [
        ("memori_server_berkas.raw", "Salinan memori (RAM) server berbagi berkas", "8 GB"),
        ("log_keamanan_server.evtx", "Log sistem & keamanan server terdampak", "214 MB"),
        ("lalu_lintas_ke_c2.pcap", "Rekaman lalu lintas ke server kendali (C2)", "96 MB"),
    ],
    "ddos": [
        ("sampel_trafik_banjir.pcap", "Sampel rekaman trafik banjir", "512 MB"),
        ("log_firewall.log", "Log firewall & penyaring trafik", "128 MB"),
        ("ringkasan_aliran.csv", "Ringkasan aliran (NetFlow) 30 menit terakhir", "22 MB"),
    ],
    "sabotase_ot": [
        ("lalu_lintas_modbus.pcap", "Rekaman lalu lintas Modbus/TCP ke pengendali genset", "64 MB"),
        ("log_workstation_teknisi.evtx", "Log login & proses workstation teknisi fasilitas", "120 MB"),
        ("konfigurasi_pengendali_genset.bin", "Salinan konfigurasi & jadwal pengendali genset", "2 MB"),
    ],
    # v5.4.2: insiden dari temuan log asli. Barang di bawah tetap simulasi; berkas log yang diimpor dicatat terpisah
    # ("sumber_temuan") dengan SHA-256 ASLI yang dihitung saat impor.
    "intrusi_log": [
        ("salinan_log_aset_terdampak.log", "Salinan log sistem aset terdampak saat diisolasi", "48 MB"),
        ("daftar_akun_dan_kunci.json", "Daftar akun, kunci SSH, dan hak akses saat kejadian", "1 MB"),
        ("koneksi_aktif_aset.csv", "Koneksi jaringan aktif aset terdampak", "3 MB"),
    ],
    "backup_dimatikan": [
        ("riwayat_konfigurasi_backup.json", "Riwayat perubahan jadwal pencadangan", "1 MB"),
        ("jejak_login_admin.log", "Jejak login admin (SSH)", "34 MB"),
        ("potret_akun_dan_hak_akses.json", "Daftar akun & hak akses saat kejadian", "2 MB"),
    ],
}

# v5.4.2: insiden dari temuan log asli tidak memakai barang templat yang menyebut perangkat lain (mis. workstation
# teknisi); hanya barang umum aset terdampak, ditambah rekaman Modbus untuk temuan OT.
ARTEFAK_TEMUAN: dict[str, list[tuple[str, str, str]]] = {
    "intrusi_log": ARTEFAK["intrusi_log"],
    "sabotase_ot": [
        ("lalu_lintas_modbus.pcap", "Rekaman lalu lintas Modbus/TCP ke pengendali genset", "64 MB"),
        ("konfigurasi_pengendali_genset.bin", "Salinan konfigurasi & jadwal pengendali genset", "2 MB"),
    ],
}

# Aksi di buku rantai bukti (juga dicerminkan ke log audit)
BUKTI_DIAMANKAN = "BUKTI_DIAMANKAN"
BUKTI_GAGAL = "PENGAMBILAN_BUKTI_GAGAL"
ISOLASI_DARURAT = "ISOLASI_DARURAT"
BUKTI_DIVERIFIKASI = "BUKTI_DIVERIFIKASI"
VERIFIKASI_GAGAL = "VERIFIKASI_BUKTI_GAGAL"
PERINGATAN_DITUTUP = "PERINGATAN_DITUTUP"   # triase: Operator menutup peringatan WASPADA beralasan


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest(barang: list[dict]) -> str:
    """Sidik jari gabungan: urutan nama berkas tetap, jadi satu angka mewakili seluruh kantong."""
    return _sha256("\n".join(f"{b['nama']}:{b['sha256']}" for b in sorted(barang, key=lambda b: b["nama"])).encode())


def _berkas_nomor() -> Path | None:
    jalur = os.getenv("NS_BUKTI_NOMOR_FILE")
    if jalur:
        return Path(jalur)
    if os.getenv("NS_AUDIT_KEY"):
        return Path("data/nomor_bukti.json")
    return None


class RantaiBukti:
    def __init__(self, buku: LogAudit, pencacah: PencacahIR) -> None:
        self.buku = buku
        self._pencacah = pencacah
        self._brankas: dict[str, dict[str, bytes]] = {}   # nomor bukti -> {nama berkas: isi}
        self._cache_utuh: tuple[int, dict] | None = None

    # -- pengambilan ---------------------------------------------------------------
    def amankan(self, *, layanan_id: str, insiden_id: str, skenario: str, petugas: str,
                metode: str, susulan: bool = False, sumber_temuan: dict | None = None) -> dict:
        """Salin barang bukti ke brankas, hitung SHA-256, catat berita acara. Mengembalikan entri buku."""
        nomor, uid = self._pencacah.berikutnya("BB")
        isi: dict[str, bytes] = {}
        barang = []
        for nama, ket, ukuran in (ARTEFAK_TEMUAN.get(skenario, ARTEFAK["intrusi_log"]) if sumber_temuan
                                  else ARTEFAK[skenario]):
            data = f"SIMULASI|{nomor}|{layanan_id}|{nama}|".encode() + secrets.token_bytes(512)
            isi[nama] = data
            barang.append({"nama": nama, "ket": ket, "ukuran": ukuran, "sha256": _sha256(data)})
        self._brankas[nomor] = isi
        return self.buku.catat(petugas, BUKTI_DIAMANKAN, {
            "nomor": nomor, "uuid": uid, "insiden_id": insiden_id, "layanan": layanan_id, "skenario": skenario,
            "metode": metode, "susulan": susulan, "barang": barang, "sha256": _manifest(barang),
            "lokasi": f"brankas-bukti/{nomor} (simulasi, hanya-baca)",
            "diambil": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        } | ({"sumber_temuan": sumber_temuan} if sumber_temuan else {}))

    def catat(self, petugas: str, aksi: str, detail: dict) -> dict:
        """Halaman berita acara lain: kegagalan pengambilan, isolasi darurat, hasil verifikasi."""
        return self.buku.catat(petugas, aksi, detail)

    # -- verifikasi -----------------------------------------------------------------
    def periksa(self, nomor: str) -> tuple[bool, str]:
        """Pemeriksaan cepat (dipakai tiap detak untuk tampilan): halaman berita acara masih utuh,
        dan isi brankas menghasilkan sidik jari yang SAMA dengan yang tercatat."""
        catatan = self.buku.cari(BUKTI_DIAMANKAN, nomor=nomor)
        if len(catatan) != 1:
            return False, f"berita acara {nomor} tidak ditemukan"
        e = catatan[0]
        if not self.buku.entri_utuh(e):
            return False, f"halaman berita acara {nomor} telah diubah"
        isi = self._brankas.get(nomor)
        if isi is None:
            return False, f"salinan bukti {nomor} tidak ada di brankas"
        for b in e["detail"]["barang"]:
            data = isi.get(b["nama"])
            if data is None:
                return False, f"berkas {b['nama']} hilang dari brankas"
            if _sha256(data) != b["sha256"]:
                return False, f"sidik jari {b['nama']} berubah"
        if _manifest(e["detail"]["barang"]) != e["detail"]["sha256"]:
            return False, "sidik jari gabungan tidak cocok"
        return True, f"SHA-256 {e['detail']['sha256'][:12]}… cocok"

    def verifikasi_penuh(self, nomor: str) -> tuple[bool, str]:
        """Sebelum pemulihan: periksa barang bukti DAN seluruh rantai buku dari halaman pertama."""
        rantai = self.buku.verifikasi()
        if not rantai["utuh"]:
            return False, f"buku rantai bukti rusak ({rantai['pesan']})"
        return self.periksa(nomor)

    def status_buku(self) -> dict:
        """Ringkasan untuk tampilan; verifikasi rantai di-cache selama jumlah halaman tidak berubah."""
        n = self.buku.jumlah
        if not self._cache_utuh or self._cache_utuh[0] != n:
            v = self.buku.verifikasi()
            self._cache_utuh = (n, {"jumlah": n, "utuh": v["utuh"], "pesan": v["pesan"]})
        return self._cache_utuh[1]

    def daftar(self, batas: int = 50) -> list[dict]:
        return self.buku.daftar(batas)

    # -- khusus pengujian -------------------------------------------------------------
    def _uji_rusak_brankas(self, nomor: str, nama: str) -> None:
        """Hanya untuk pengujian otomatis: sengaja mengubah satu byte salinan bukti."""
        data = bytearray(self._brankas[nomor][nama])
        data[-1] ^= 0xFF
        self._brankas[nomor][nama] = bytes(data)


RANTAI = RantaiBukti(LogAudit("NS_BUKTI_FILE", "data/rantai_bukti.jsonl", "buku rantai bukti"),
                     PencacahIR(_berkas_nomor()))
