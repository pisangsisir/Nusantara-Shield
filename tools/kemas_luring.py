# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
kemas_luring.py — membuat paket pasang LURING untuk jaringan air-gapped.

Dijalankan SEKALI di komputer yang terhubung internet. Hasilnya satu zip berisi kode, semua pustaka
(berkas .whl), pemasang tools/pasang_luring.py (disalin ke akar paket), dan daftar sidik jari SHA256SUMS.
Di posko, zip itu dibawa lewat media yang diperiksa lalu dipasang tanpa internet.

Pemakaian (dari folder proyek):
    python tools/kemas_luring.py                                   → untuk komputer ini
    python tools/kemas_luring.py --platform win_amd64 --python 3.12 → untuk Windows 64-bit, Python 3.12
    python tools/kemas_luring.py --platform macosx_14_0_arm64 --python 3.12 → Mac Apple Silicon (macOS 14+)
    python tools/kemas_luring.py --platform manylinux2014_x86_64 --python 3.12
Batas: versi Python di posko harus sama dengan --python; ukuran paket ≈60–80 MB (numpy, scipy, scikit-learn).
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from kemas_rilis import AKAR, NAMA, ikut  # noqa: E402  (aturan pengecualian sama dengan zip rilis)
from pasang_luring import DAFTAR, buat_daftar, sidik  # noqa: E402


def kebutuhan_untuk(platform: str | None) -> str:
    """Isi requirements untuk paket. Saat mengemas untuk sistem operasi LAIN, pip menilai penanda
    sys_platform memakai komputer pengemas, bukan target. Karena itu ekstra uvicorn[standard]
    (uvloop dsb., tidak dibutuhkan aplikasi ini) diganti uvicorn polos, dan colorama (dibutuhkan
    click di Windows) ditambahkan secara eksplisit untuk target Windows."""
    isi = (AKAR / "requirements.txt").read_text(encoding="utf-8")
    if not platform:
        return isi
    isi = isi.replace("uvicorn[standard]", "uvicorn")
    if platform.startswith("win"):
        isi += "\ncolorama\n"
    return isi


def perintah_unduh(tujuan: Path, platform: str | None, python: str | None,
                   kebutuhan: Path | None = None) -> list[str]:
    cmd = [sys.executable, "-m", "pip", "download", "-r", str(kebutuhan or AKAR / "requirements.txt"),
           "-d", str(tujuan), "--only-binary=:all:"]
    if platform:
        cmd += ["--platform", platform, "--implementation", "cp"]
    if python:
        cmd += ["--python-version", python]
    return cmd


def unduh_pip(tujuan: Path, platform: str | None, python: str | None) -> None:
    kebutuhan = tujuan.parent / "requirements.txt"          # salinan di paket, sudah disesuaikan target
    subprocess.run(perintah_unduh(tujuan, platform, python, kebutuhan), check=True)


def kemas(keluar: Path, platform: str | None = None, python: str | None = None,
          unduh: Callable[[Path, str | None, str | None], None] = unduh_pip) -> Path:
    """Membangun zip paket luring dan mengembalikan jalurnya."""
    label = platform or "komputer-ini"
    nama_paket = f"{NAMA}-luring-{label}"
    with tempfile.TemporaryDirectory() as sementara:
        akar_paket = Path(sementara) / nama_paket
        for p in sorted(x for x in AKAR.rglob("*") if x.is_file() and ikut(x)):
            relatif = p.relative_to(AKAR)
            if relatif.parts[0] == "wheels" or relatif.as_posix() in (DAFTAR, "pasang_luring.py"):
                continue          # sisa paket lama (bila dijalankan dari dalam paket luring) tidak ikut
            tujuan = akar_paket / relatif
            tujuan.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, tujuan)
        if (akar_paket / ".env").exists():
            raise RuntimeError(".env terdeteksi di paket — dibatalkan")
        shutil.copy2(AKAR / "tools" / "pasang_luring.py", akar_paket / "pasang_luring.py")
        (akar_paket / "requirements.txt").write_text(kebutuhan_untuk(platform), encoding="utf-8")
        (akar_paket / "wheels").mkdir()
        unduh(akar_paket / "wheels", platform, python)
        (akar_paket / DAFTAR).write_text(buat_daftar(akar_paket), encoding="utf-8")
        sidik_daftar = sidik(akar_paket / DAFTAR)
        keluar.mkdir(parents=True, exist_ok=True)
        zip_jalur = keluar / f"{nama_paket}.zip"
        with zipfile.ZipFile(zip_jalur, "w", zipfile.ZIP_DEFLATED) as z:
            for p in sorted(akar_paket.rglob("*")):
                if p.is_file():
                    z.write(p, f"{nama_paket}/{p.relative_to(akar_paket).as_posix()}")
    print(f"✓ {zip_jalur} · {zip_jalur.stat().st_size / 1_048_576:.1f} MB")
    print(f"  Sidik jari {DAFTAR} : {sidik_daftar}")
    print(f"  Sidik jari zip        : {sidik(zip_jalur)}")
    print("  Tulis kedua sidik jari ini di berita acara serah terima paket.")
    return zip_jalur


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Membuat paket pasang luring Nusantara Shield.")
    ap.add_argument("--platform", help="target, mis. win_amd64, macosx_14_0_arm64, manylinux2014_x86_64")
    ap.add_argument("--python", help="versi Python target, mis. 3.12 (wajib bila --platform diisi)")
    ap.add_argument("--keluar", default=str(AKAR / "dist"), help="folder hasil (bawaan: dist/)")
    arg = ap.parse_args(argv)
    if arg.platform and not arg.python:
        ap.error("--python wajib diisi bersama --platform")
    kemas(Path(arg.keluar), arg.platform, arg.python)
    return 0


if __name__ == "__main__":
    sys.exit(main())
