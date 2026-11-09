#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
Membangun berkas unduhan situs (situs/unduh/) dari sumber di repo, lalu menulis daftar unduhan beserta sidik jari
SHA-256-nya ke situs/index.html. Dijalankan pembuat rilis setelah dokumen berubah; hasilnya ikut di-commit.

Analogi: juru arsip yang mencetak ulang semua lampiran dari naskah induknya, memberi nomor segel pada tiap
lampiran, lalu memperbarui daftar isi map. Tidak ada lampiran yang ditulis tangan terpisah dari naskahnya.

Yang dibuat:
  - Proposal dan Dokumentasi Teknis: Markdown → PDF A4, memakai huruf situs (tanpa internet).
  - Dek presentasi: 9 slide → PDF dan PPTX (tiap slide satu gambar; sumbernya presentation/index.html).
  - Disalin apa adanya: Panduan Belajar PDF, poster PDF, dua contoh LAPSIT, dan contoh log (zip).

Kebutuhan (hanya di komputer pembuat rilis, bukan di server satuan): python-markdown, Playwright + Chromium,
python-pptx, Pillow. Pemakaian dari akar repo:  python3 tools/bangun_situs.py
"""
from __future__ import annotations

import hashlib
import html
import io
import re
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

AKAR = Path(__file__).resolve().parent.parent
SITUS = AKAR / "situs"
UNDUH = SITUS / "unduh"
MULAI, AKHIR = "<!-- UNDUH:MULAI -->", "<!-- UNDUH:AKHIR -->"
JUMLAH_SLIDE = 9

GAYA_DOKUMEN = """
@font-face { font-family: Bricolage; src: url("%(huruf)s/bricolage-grotesque.woff2"); font-weight: 200 800; }
@font-face { font-family: Jakarta; src: url("%(huruf)s/plus-jakarta-sans.woff2"); font-weight: 200 800; }
@font-face { font-family: Jakarta; src: url("%(huruf)s/plus-jakarta-sans-italic.woff2"); font-weight: 200 800; font-style: italic; }
@font-face { font-family: JetBrains; src: url("%(huruf)s/jetbrains-mono.woff2"); font-weight: 100 800; }
@page { size: A4; margin: 18mm 17mm 18mm 17mm; }
body { font: 10pt/1.55 Jakarta, sans-serif; color: #172033; }
h1, h2, h3, h4 { font-family: Bricolage, sans-serif; line-height: 1.15; color: #172033; break-after: avoid; }
h1 { font-size: 22pt; font-stretch: 85%%; margin: 0 0 10pt; }
h2 { font-size: 15pt; margin: 18pt 0 6pt; border-bottom: 1.5pt solid #172033; padding-bottom: 3pt; }
h3 { font-size: 12pt; margin: 12pt 0 4pt; }
table { border-collapse: collapse; width: 100%%; margin: 6pt 0 10pt; font-size: 8.5pt; break-inside: auto; }
th, td { border: .5pt solid #c6cdc4; padding: 3pt 5pt; vertical-align: top; text-align: left; }
th { background: #e3e8e1; }
tr { break-inside: avoid; }
code, pre { font-family: JetBrains, monospace; font-size: 8.5pt; }
pre { background: #eef1ec; padding: 6pt 8pt; white-space: pre-wrap; border-radius: 3pt; }
blockquote { border-left: 3pt solid #b4232c; margin: 8pt 0; padding: 2pt 10pt; color: #3a4556; }
img, svg { max-width: 100%%; height: auto; }
a { color: #172033; }
.kepala-dokumen { font-size: 8pt; color: #5b6573; margin-bottom: 14pt; }
"""

DOKUMEN = [
    ("docs/01-Proposal-Solusi-Nusantara-Shield.md", "Proposal-Solusi-Nusantara-Shield.pdf", "Proposal Solusi",
     "Masalah, solusi, keunggulan taktis, kelayakan penerapan, peta kriteria penilaian, dan asal setiap angka"),
    ("docs/02-Dokumentasi-Teknis-Nusantara-Shield.md", "Dokumentasi-Teknis-Nusantara-Shield.pdf", "Dokumentasi Teknis",
     "Arsitektur, aturan deteksi, keamanan posko, SOP respons insiden, Drill Kesiapan, pemasangan, dan uji"),
]
SALIN = [
    ("docs/03-Panduan-Belajar-Nusantara-Shield.pdf", "Panduan-Belajar-Nusantara-Shield.pdf", "Panduan Belajar",
     "Untuk pembaca non-IT: dari nol sampai bisa menjelaskan sistem ini"),
    ("docs/poster/poster-nusantara-shield.pdf", "Poster-Nusantara-Shield.pdf", "Poster", "Satu halaman A4"),
    ("docs/contoh-lapsit/contoh-lapsit-insiden.pdf", "Contoh-LAPSIT-insiden.pdf", "Contoh LAPSIT (insiden)",
     "Laporan situasi yang dicetak sistem saat insiden ditangani"),
    ("docs/contoh-lapsit/contoh-lapsit-kondisi-normal.pdf", "Contoh-LAPSIT-kondisi-normal.pdf", "Contoh LAPSIT (rutin)",
     "Laporan situasi saat kondisi normal"),
]


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def ukuran(p: Path) -> str:
    n = p.stat().st_size
    return f"{n / 1_048_576:.1f} MB".replace(".", ",") if n >= 1_048_576 else f"{round(n / 1024)} KB"


def md_ke_pdf(halaman, sumber: Path, tujuan: Path) -> None:
    import markdown
    teks = sumber.read_text(encoding="utf-8")
    isi = markdown.markdown(teks, extensions=["tables", "fenced_code", "sane_lists", "attr_list"])
    gaya = GAYA_DOKUMEN % {"huruf": (SITUS / "huruf").as_uri()}
    dok = (f"<!doctype html><html lang='id'><head><meta charset='utf-8'><style>{gaya}</style></head><body>"
           f"<p class='kepala-dokumen'>Nusantara Shield · Kartika Cyber Hackathon 2026 · sumber: {html.escape(sumber.name)} "
           f"di github.com/pisangsisir/Nusantara-Shield</p>{isi}</body></html>")
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8", dir=sumber.parent) as f:
        f.write(dok)                       # di folder sumbernya: gambar relatif di Markdown tetap ditemukan
        sementara = Path(f.name)
    try:
        halaman.goto(sementara.as_uri())
        halaman.wait_for_timeout(600)
        halaman.pdf(path=str(tujuan), format="A4", print_background=True, display_header_footer=True,
                    header_template="<span></span>",
                    footer_template="<div style='font-size:7pt;width:100%;text-align:center;color:#5b6573'>"
                                    "Halaman <span class='pageNumber'></span> dari <span class='totalPages'></span></div>",
                    margin={"top": "16mm", "bottom": "16mm", "left": "16mm", "right": "16mm"})
    finally:
        sementara.unlink(missing_ok=True)


def dek(peramban) -> tuple[Path, Path]:
    from PIL import Image
    from pptx import Presentation
    from pptx.util import Emu
    hal = peramban.new_page(viewport={"width": 1920, "height": 1080})
    gambar = []
    for n in range(1, JUMLAH_SLIDE + 1):
        hal.goto((AKAR / "presentation/index.html").as_uri() + f"#{n}")
        hal.reload()
        hal.wait_for_timeout(9000)          # animasi masuk tiap slide selesai
        gambar.append(Image.open(io.BytesIO(hal.screenshot())).convert("RGB"))
    hal.close()
    pdf, pptx = UNDUH / "Slide-Nusantara-Shield.pdf", UNDUH / "Slide-Nusantara-Shield.pptx"
    gambar[0].save(pdf, save_all=True, append_images=gambar[1:], resolution=144, quality=90)
    pres = Presentation()
    pres.slide_width, pres.slide_height = Emu(12192000), Emu(6858000)
    for g in gambar:
        s = pres.slides.add_slide(pres.slide_layouts[6])
        b = io.BytesIO()
        g.save(b, "JPEG", quality=88)
        b.seek(0)
        s.shapes.add_picture(b, 0, 0, width=pres.slide_width, height=pres.slide_height)
    pres.save(pptx)
    return pdf, pptx


def zip_contoh_log() -> Path:
    tujuan = UNDUH / "contoh-log.zip"
    with zipfile.ZipFile(tujuan, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted((AKAR / "docs/contoh-log").iterdir()):
            info = zipfile.ZipInfo(f"contoh-log/{p.name}", date_time=(2026, 1, 1, 0, 0, 0))   # zip stabil
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, p.read_bytes())
    return tujuan


def baris(judul: str, ket: str, berkas: list[Path]) -> str:
    sel = "<br>".join(f"<a class=\"berkas\" href=\"unduh/{html.escape(p.name)}\" download>{html.escape(p.suffix[1:].upper())}"
                      f" · {ukuran(p)}</a> <span class=\"sidik\">{sha256(p)}</span>" for p in berkas)
    return f"          <tr><td>{html.escape(judul)}</td><td>{html.escape(ket)}</td><td>{sel}</td></tr>"


def main() -> int:
    from playwright.sync_api import sync_playwright
    UNDUH.mkdir(exist_ok=True)
    for lama in UNDUH.iterdir():
        lama.unlink()
    daftar = []
    with sync_playwright() as p:
        b = p.chromium.launch()
        hal = b.new_page()
        for sumber, nama, judul, ket in DOKUMEN:
            tujuan = UNDUH / nama
            md_ke_pdf(hal, AKAR / sumber, tujuan)
            daftar.append((judul, ket, [tujuan]))
        pdf, pptx = dek(b)
        daftar.insert(1, ("Dek presentasi", f"{JUMLAH_SLIDE} slide yang disajikan ke Dewan Juri (PPTX: tiap slide satu gambar)",
                          [pdf, pptx]))
        b.close()
    for sumber, nama, judul, ket in SALIN:
        shutil.copyfile(AKAR / sumber, UNDUH / nama)
        daftar.append((judul, ket, [UNDUH / nama]))
    daftar.append(("Contoh log", "auth.log, firewall, CSV, Wazuh alerts.json, dan Suricata eve.json (sintetis) untuk "
                   "mencoba fitur impor", [zip_contoh_log()]))
    (UNDUH / "SHA256SUMS").write_text("".join(f"{sha256(p)}  {p.name}\n" for _, _, bs in daftar for p in bs),
                                      encoding="utf-8")
    indeks = SITUS / "index.html"
    teks = indeks.read_text(encoding="utf-8")
    awal, akhir = teks.index(MULAI) + len(MULAI), teks.index(AKHIR)
    teks = teks[:awal] + "\n" + "\n".join(baris(*x) for x in daftar) + "\n" + teks[akhir:]
    indeks.write_text(teks, encoding="utf-8")
    for _, _, bs in daftar:
        for p in bs:
            print(f"✓ {p.relative_to(AKAR)}  {ukuran(p)}  {sha256(p)[:16]}…")
    return 0


if __name__ == "__main__":
    sys.exit(main())
