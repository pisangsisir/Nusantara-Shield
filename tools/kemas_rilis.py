# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
kemas_rilis.py — membuat zip rilis yang BERSIH (tanpa .venv, cache, rahasia, maupun data runtime).

Analogi: mengirim resep ke juri, bukan mengirim dapur beserta kompornya. Folder .venv berisi
Python yang dirakit khusus untuk komputer Anda; di komputer lain ia rusak dan hanya membuat zip
membengkak (versi lama: ≈28 MB, ≈4.200 berkas). Juri cukup menjalankan `pip install -r requirements.txt`.

Pemakaian (dari folder proyek, di Mac/Linux/Windows):
    python tools/kemas_rilis.py            → dist/nusantara-shield-v<versi>.zip (versi dari app/versi.py)
    python tools/kemas_rilis.py --periksa  → hanya menampilkan daftar berkas, tanpa membuat zip
Aturan pengecualian sama dengan .gitignore.
"""

from __future__ import annotations

import fnmatch
import re
import sys
import zipfile
from pathlib import Path

AKAR = Path(__file__).resolve().parent.parent


def baca_versi(akar: Path = AKAR) -> str:
    """Nomor versi dari app/versi.py, dibaca sebagai teks (alat ini tidak mengimpor paket app)."""
    cocok = re.search(r'^VERSI = "(\d+\.\d+\.\d+)"$', (akar / "app" / "versi.py").read_text(encoding="utf-8"), re.M)
    if not cocok:
        raise SystemExit("app/versi.py tidak berisi baris VERSI = \"x.y.z\"")
    return cocok.group(1)


VERSI = baca_versi()
NAMA = f"nusantara-shield-v{VERSI}"
FOLDER_DIBUANG = {".venv", "venv", "env", "data", "__pycache__", ".pytest_cache", "__MACOSX", "dist", ".git", ".idea",
                  ".vscode"}
BERKAS_DIBUANG = [".env", "*.pyc", "*.pyo", ".DS_Store", "Thumbs.db", "*.zip", "*.tmp"]


def ikut(jalur: Path) -> bool:
    relatif = jalur.relative_to(AKAR)
    if any(bagian in FOLDER_DIBUANG for bagian in relatif.parts[:-1]):
        return False
    return not any(fnmatch.fnmatch(jalur.name, pola) for pola in BERKAS_DIBUANG)


def main() -> int:
    berkas = sorted(p for p in AKAR.rglob("*") if p.is_file() and ikut(p))
    if any(p.name == ".env" for p in berkas):                      # pertahanan berlapis: rahasia tidak boleh ikut
        print("✖ .env terdeteksi di daftar kemasan — dibatalkan.")
        return 1
    for p in berkas:
        print("  +", p.relative_to(AKAR).as_posix())
    if "--periksa" in sys.argv:
        print(f"{len(berkas)} berkas akan dikemas (mode periksa, zip tidak dibuat).")
        return 0
    tujuan = AKAR / "dist" / f"{NAMA}.zip"
    tujuan.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(tujuan, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in berkas:
            z.write(p, f"{NAMA}/{p.relative_to(AKAR).as_posix()}")
    print(f"✓ {tujuan.relative_to(AKAR)} · {len(berkas)} berkas · {tujuan.stat().st_size / 1024:.0f} KB")
    print("  Tanpa .venv, data/, .env, cache, dan sampah sistem. Penerima cukup: pip install -r requirements.txt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
