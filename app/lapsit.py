# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
lapsit.py — Membuat laporan situasi dalam format PDF (label resmi diambil dari kamus istilah).

Analogi: notulen rapat darurat yang dicetak otomatis. Isinya ringkasan
status semua layanan, insiden yang sedang berjalan, dan bukti bahwa buku
catatan audit masih utuh.

Susunan mengikuti laporan insiden formal (gaya SANS/NIST SP 800-61): ringkasan eksekutif naratif, status dan
dampak operasional, kronologi serta tindakan playbook bercap waktu dan beraktor, tabel indikator kompromi (IoC),
peringatan dengan teknik ATT&CK, tindak lanjut yang disarankan (aturan tetap, bukan AI), integritas log audit beserta cara memverifikasinya, lalu pengesahan. Semua isi
diambil dari keadaan sistem saat dicetak; tidak ada angka atau kalimat dampak yang ditulis tetap di template.

Kop laporan: logo Nusantara Shield digambar sebagai VEKTOR langsung dari static/logo.svg (satu sumber dengan dasbor),
tanpa pustaka tambahan dan tanpa internet. Kop memakai identitas proyek sendiri; sengaja tidak meniru kop surat,
lambang, atau stempel instansi mana pun. Setiap halaman memuat nomor laporan dan "Halaman x dari y".
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
import os
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.platypus.flowables import HRFlowable
from xml.sax.saxutils import escape

from .data_contoh import BATAS_JAM_BACKUP, DAMPAK_OPERASIONAL, GANGGUAN_SKENARIO
from .istilah import ISTILAH, nama_manajemen
from .mitre import ringkas as ringkas_mitre
from .versi import VERSI

WARNA_STATUS = {"hijau": colors.HexColor("#1f8a4c"),
                "kuning": colors.HexColor("#b7791f"),
                "merah": colors.HexColor("#c0392b")}


ZONA_WAKTU = {"WIB": 7, "WITA": 8, "WIT": 9}
LATAR = colors.HexColor("#F3F5F8")
GARIS = colors.HexColor("#B8C0CC")


def zona() -> tuple[str, timezone]:
    """Zona waktu laporan: NS_ZONA_WAKTU = WIB (bawaan) | WITA | WIT, sesuai lokasi satuan."""
    nama = os.getenv("NS_ZONA_WAKTU", "WIB").upper()
    nama = nama if nama in ZONA_WAKTU else "WIB"
    return nama, timezone(timedelta(hours=ZONA_WAKTU[nama]), nama)


BULAN = ("Januari", "Februari", "Maret", "April", "Mei", "Juni", "Juli", "Agustus", "September", "Oktober",
         "November", "Desember")


def tulis_waktu(w: datetime, nama: str, detik: bool = True, tabel: bool = False) -> str:
    """Penulisan waktu menurut PUEBI: jam, menit, dan detik dipisah titik (pukul 08.02.01).
    Di kalimat: '13 November 2026 pukul 08.02.01 WIB'; di tabel (ringkas): '13-11-2026 08.02.01 WIB'."""
    jam = w.strftime("%H.%M.%S" if detik else "%H.%M")
    if tabel:
        return f"{w:%d-%m-%Y} {jam} {nama}"
    return f"{w.day} {BULAN[w.month - 1]} {w.year} pukul {jam} {nama}"


def waktu_lokal(iso: str | None, detik: bool = True, tabel: bool = False) -> str:
    """ISO-8601 (UTC) → waktu lokal satuan menurut PUEBI (lihat tulis_waktu). Teks yang bukan waktu dikembalikan
    apa adanya."""
    if not iso:
        return "—"
    nama, tz = zona()
    try:
        w = datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(tz)
    except ValueError:
        return iso
    return tulis_waktu(w, nama, detik, tabel)


# Istilah asing dicetak miring (PUEBI). Nama diri (Modbus, MITRE ATT&CK) dan singkatan tidak dimiringkan.
ASING = re.compile(r"(?<![>\w/.-])(ransomware|server|login|admin|playbook|firewall|Write Multiple Registers)(?![\w/-]|\.\w)",
                   re.IGNORECASE)


def _miring(teks: str) -> str:
    """Memiringkan istilah asing pada teks yang SUDAH di-escape (aman: tidak menyentuh isi tag atau jalur berkas)."""
    return ASING.sub(r"<i>\1</i>", teks)


def _teknik(teks: str) -> str:
    """'T1486 Data Encrypted for Impact; T0886 …' → nama teknik (bahasa Inggris) dicetak miring, nomornya tegak."""
    return re.sub(r"(T\d{4}(?:\.\d{3})?) ([^;]+?)(?=( \(ICS\))?(;|$))", r"\1 <i>\2</i>", teks)


def _kecil(teks: str) -> str:
    """Huruf pertama dikecilkan agar enak disambung di tengah kalimat; singkatan (IOC, SIMRS) tetap utuh."""
    return teks[:1].lower() + teks[1:] if teks[:2].isupper() is False else teks


def _koma(x: float) -> str:
    return f"{x:.1f}".replace(".", ",")


def dampak_operasional(l: dict, ins_rinci: dict | None) -> str:
    """Kalimat dampak terhadap misi layanan, dari status nyata + profil layanan (perkiraan, data contoh)."""
    prof = DAMPAK_OPERASIONAL.get(l.get("id"), {})
    misi, kontinjensi = prof.get("misi", "layanan"), prof.get("kontinjensi", "prosedur manual")
    if l.get("insiden"):
        if ins_rinci and ins_rinci.get("ir"):
            if prof.get("saat_diisolasi"):
                return f"Diisolasi: {prof['saat_diisolasi']}. Prosedur darurat: {kontinjensi}."
            return f"Diisolasi: {misi} dihentikan sementara dengan sengaja. Prosedur darurat: {kontinjensi}."
        tm = l["insiden"].get("temuan")
        if tm:      # v5.4.2: dari temuan log asli → yang terbukti hanya isi temuannya, bukan gangguan khas templat
            gangguan = (f"temuan {tm['nama'].lower()} pada {', '.join(tm.get('aset_nama') or tm['aset'])}; "
                        f"{misi} berisiko terganggu bila tidak ditangani")
        else:
            gangguan = GANGGUAN_SKENARIO.get(l["insiden"]["skenario"], "{misi} terganggu").format(misi=misi)
        return f"{gangguan[:1].upper()}{gangguan[1:]}. Prosedur darurat siap: {kontinjensi}."
    if l.get("status") == "kuning":
        alasan = l.get("alasan", "")
        return (f"Layanan berjalan. Risiko: {alasan[:1].lower()}{alasan[1:]}; pemulihan bisa lebih lama bila "
                f"terjadi insiden.")
    return "Layanan berjalan normal."


LOGO_SVG = Path(__file__).resolve().parent.parent / "static" / "logo.svg"
NAVY = colors.HexColor("#0A1120")
HIJAU = colors.HexColor("#1F8A4C")       # hijau merek versi cetak (neon #3EF0A1 terlalu pucat di kertas putih)
ABU = colors.HexColor("#5A6678")
_TOKEN = re.compile(r"[MLCQVHZ]|-?\d*\.?\d+(?:[eE][-+]?\d+)?")


def _jalur(c, d: str):
    """Data jalur SVG (perintah absolut M L C Q V H Z, cukup untuk logo kita) → objek jalur ReportLab."""
    tok = _TOKEN.findall(d)
    p, i, x, y, perintah = c.beginPath(), 0, 0.0, 0.0, None
    angka = lambda: float(tok[i])
    while i < len(tok):
        if tok[i].isalpha():
            perintah, i = tok[i], i + 1
            if perintah == "Z":
                p.close()
            continue
        if perintah in ("M", "L"):
            x, y = angka(), float(tok[i + 1]); i += 2
            (p.moveTo if perintah == "M" else p.lineTo)(x, y)
            perintah = "L" if perintah == "M" else perintah
        elif perintah == "V":
            y = angka(); i += 1; p.lineTo(x, y)
        elif perintah == "H":
            x = angka(); i += 1; p.lineTo(x, y)
        elif perintah == "C":
            v = [float(s) for s in tok[i:i + 6]]; i += 6
            p.curveTo(*v); x, y = v[4], v[5]
        elif perintah == "Q":                    # kuadrat → kubik
            qx, qy, ex, ey = (float(s) for s in tok[i:i + 4]); i += 4
            p.curveTo(x + 2 / 3 * (qx - x), y + 2 / 3 * (qy - y), ex + 2 / 3 * (qx - ex), ey + 2 / 3 * (qy - ey), ex, ey)
            x, y = ex, ey
        else:
            raise ValueError(f"perintah jalur tidak didukung: {perintah}")
    return p


def gambar_logo(c, x: float, y: float, ukuran: float) -> bool:
    """Gambar logo di kotak persegi (x, y = sudut kiri bawah). False bila berkas logo tidak terbaca (kop tetap jadi)."""
    try:
        akar = ET.parse(LOGO_SVG).getroot()
    except (OSError, ET.ParseError):
        return False
    ns = "{http://www.w3.org/2000/svg}"
    lebar = float(akar.get("viewBox", "0 0 512 512").split()[2])
    c.saveState()
    c.translate(x, y + ukuran)
    c.scale(ukuran / lebar, -ukuran / lebar)                     # sumbu y SVG ke bawah, PDF ke atas

    def lukis(el, warisan: dict):
        a = {**warisan, **{k: v for k, v in el.attrib.items() if k in (
            "fill", "stroke", "stroke-width", "stroke-opacity", "fill-opacity", "stroke-linecap")}}
        tag = el.tag.replace(ns, "")
        if tag in ("svg", "g"):
            for anak in el:
                lukis(anak, a)
            return
        if tag not in ("path", "rect", "circle"):
            return
        isi = a.get("fill", "#000000") not in ("none",)
        garis = a.get("stroke", "none") != "none" and float(a.get("stroke-width", "1")) > 0
        if isi:
            c.setFillColor(colors.HexColor(a.get("fill", "#000000")))
            c.setFillAlpha(float(a.get("fill-opacity", "1")))
        if garis:
            c.setStrokeColor(colors.HexColor(a["stroke"]))
            c.setStrokeAlpha(float(a.get("stroke-opacity", "1")))
            c.setLineWidth(float(a.get("stroke-width", "1")))
            c.setLineJoin(1)
            c.setLineCap(1 if a.get("stroke-linecap") == "round" else 0)
        if tag == "path":
            c.drawPath(_jalur(c, el.get("d", "")), stroke=int(garis), fill=int(isi))
        elif tag == "rect":
            c.rect(float(el.get("x")), float(el.get("y")), float(el.get("width")), float(el.get("height")),
                   stroke=int(garis), fill=int(isi))
        else:
            c.circle(float(el.get("cx")), float(el.get("cy")), float(el.get("r")), stroke=int(garis), fill=int(isi))

    try:
        lukis(akar, {})
    except (ValueError, TypeError, IndexError):
        c.restoreState()
        return False
    c.restoreState()
    return True


class _KanvasBernomor(rl_canvas.Canvas):
    """Kanvas yang menunda penulisan halaman agar kaki halaman bisa memuat "Halaman x dari y"."""

    def __init__(self, *a, kop=None, **kw):
        super().__init__(*a, **kw)
        self._halaman, self._kop = [], kop

    def showPage(self):
        self._halaman.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._halaman)
        for keadaan in self._halaman:
            self.__dict__.update(keadaan)
            self._kop(self, self._pageNumber, total)
            super().showPage()
        super().save()


def _penggambar_kop(nomor: str, waktu: str, jenis: str):
    """Kop dan kaki di setiap halaman: logo + identitas proyek di kiri, jenis/nomor/waktu laporan di kanan."""
    lebar, tinggi = A4
    kiri, kanan = 18 * mm, lebar - 18 * mm

    def gambar(c, halaman: int, total: int):
        c.saveState()
        atas = tinggi - 12 * mm
        gambar_logo(c, kiri, atas - 19 * mm, 19 * mm)
        c.setFillColor(NAVY)
        c.setFont("Helvetica-Bold", 14)
        c.drawString(kiri + 23 * mm, atas - 7 * mm, "NUSANTARA SHIELD")
        c.setFont("Helvetica", 8.5)
        c.setFillColor(ABU)
        c.drawString(kiri + 23 * mm, atas - 11.5 * mm, f"Posko Pertahanan Siber Luring \u00b7 v{VERSI}")
        c.drawString(kiri + 23 * mm, atas - 15.5 * mm, "Bukti dulu, baru putus.")
        c.setFillColor(NAVY)
        c.setFont("Helvetica-Bold", 11)
        c.drawRightString(kanan, atas - 6 * mm, ISTILAH["laporan"].upper())
        c.setFont("Helvetica", 8.5)
        c.drawRightString(kanan, atas - 10.5 * mm, f"Nomor: {nomor}")
        c.drawRightString(kanan, atas - 14.5 * mm, f"Dicetak: {waktu}")
        c.drawRightString(kanan, atas - 18.5 * mm, jenis)
        c.setStrokeColor(NAVY)
        c.setLineWidth(1.6)
        c.line(kiri, atas - 22 * mm, kanan, atas - 22 * mm)
        c.setStrokeColor(HIJAU)
        c.setLineWidth(0.8)
        c.line(kiri, atas - 23.2 * mm, kanan, atas - 23.2 * mm)
        # kaki halaman
        c.setStrokeColor(colors.HexColor("#B8C0CC"))
        c.setLineWidth(0.4)
        c.line(kiri, 13 * mm, kanan, 13 * mm)
        c.setFont("Helvetica", 7.5)
        c.setFillColor(ABU)
        c.drawString(kiri, 9 * mm, f"Nusantara Shield \u00b7 {nomor} \u00b7 dibuat otomatis oleh sistem \u00b7 "
                                    "dokumen latihan, seluruh data sintetis")
        c.drawRightString(kanan, 9 * mm, f"Halaman {halaman} dari {total}")
        c.restoreState()

    return gambar


def _blok_pengesahan(gaya) -> Table:
    """Dua kolom tanda tangan: Operator jaga yang membuat laporan, dan pejabat yang mengetahui."""
    mengetahui = "/".join(reversed(nama_manajemen()))          # urutan dibalik: kepala seksi dulu, lalu komandan
    sel = lambda judul: [Paragraph(escape(judul), gaya["Normal"]), Spacer(1, 10 * mm),
                         Paragraph("( ........................................ )", gaya["Normal"]),
                         Paragraph("Nama, pangkat/NRP, tanggal", gaya["Normal"])]
    t = Table([[sel(ISTILAH["ttd_pembuat"]), sel(f"{ISTILAH['ttd_mengetahui']}, {mengetahui}")]],
              colWidths=[87 * mm, 87 * mm])
    t.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.4, colors.grey),
                           ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.grey),
                           ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("TOPPADDING", (0, 0), (-1, -1), 6)]))
    return t


def _gaya():
    g = getSampleStyleSheet()
    dasar = g["Normal"].clone("dasar", fontName="Helvetica", fontSize=9.5, leading=13)
    return {
        "dasar": dasar,
        "kecil": dasar.clone("kecil", fontSize=8, leading=10),
        "catatan": dasar.clone("catatan", fontSize=7.5, leading=9.5, textColor=ABU, fontName="Helvetica-Oblique"),
        "judul": dasar.clone("judul", fontName="Helvetica-Bold", fontSize=10.5, leading=13, textColor=NAVY,
                             spaceBefore=8, spaceAfter=2),
        "sub": dasar.clone("sub", fontName="Helvetica-Bold", fontSize=9.5, leading=12, textColor=NAVY,
                           spaceBefore=6, spaceAfter=3),
        "Normal": dasar,
    }


def _judul(teks: str, gaya: dict) -> list:
    return [Paragraph(teks, gaya["judul"]), HRFlowable(width="100%", thickness=0.6, color=GARIS,
                                                                spaceBefore=1, spaceAfter=4)]


def _tabel(baris: list, lebar: list, ukuran: float = 8) -> Table:
    t = Table(baris, colWidths=lebar, repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b2a3a")),
                           ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                           ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                           ("GRID", (0, 0), (-1, -1), 0.4, GARIS),
                           ("FONTSIZE", (0, 0), (-1, -1), ukuran),
                           ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    return t


def _kotak(isi: list, latar=LATAR) -> Table:
    t = Table([[isi]], colWidths=[174 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), latar), ("BOX", (0, 0), (-1, -1), 0.5, GARIS),
                           ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                           ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    return t


def _akun(nama: str) -> str:
    """Nama akun adalah pengenal sistem, bukan kata: dicetak dengan huruf mesin (Courier) apa adanya, sedangkan
    perannya (Operator, Pengamat) ditulis berhuruf kapital di teks sekitarnya. Masukan belum di-escape."""
    return f"<font face='Courier'>{escape(nama)}</font>"


def _tandai_akun(teks: str) -> str:
    """Teks yang SUDAH di-escape: kata sesudah 'akun ' dicetak sebagai nama akun (lihat _akun)."""
    return re.sub(r"\bakun ([a-z][a-z0-9_]{2,19})\b", r"akun <font face='Courier'>\1</font>", teks)


def _akun_status(teks: str) -> str:
    """Status peringatan dari telemetri ('Diisolasi oleh operator · bukti …'): nama sesudah 'oleh' adalah akun."""
    return re.sub(r"\boleh ([a-z][a-z0-9_]{2,19})(?= ·|$)", r"oleh akun <font face='Courier'>\1</font>", teks)


def _aktor(langkah: dict) -> str:
    """Teks SUDAH bermarkah (dipakai langsung di Paragraph)."""
    oleh, metode = langkah.get("oleh"), langkah.get("metode")
    cara = "otomatis melalui SOAR" if metode == "soar" else "manual"
    return f"akun {_akun(oleh)} · {cara}" if oleh else f"sistem · {cara}"


def ringkasan_eksekutif(layanan: list[dict], rincian: dict, peringatan: list[dict], hasil_audit: dict,
                        waktu_cetak: str) -> list[str]:
    """1–2 paragraf naratif: apa, kapan, bagaimana, dan dampaknya. Dirakit dari data, bukan teks tetap."""
    paragraf = []
    for l in layanan:
        ins = l.get("insiden")
        if not ins:
            continue
        r = rincian["insiden"].get(l["id"], {})
        log = ins.get("log_peringatan", [])
        tm = ins.get("temuan")
        if tm:
            kal = [f"Pada {waktu_lokal(ins['mulai'])} Operator <b>membuka insiden dari temuan log asli</b> "
                   f"{escape(tm['id'])} ({escape(tm['nama'])}, berkas impor {escape(tm['berkas'])}) di "
                   f"<b>{escape(l['nama'])}</b> ({escape(l.get('cabang', ''))}), bukan dari latihan."]
        else:
            kal = [f"Pada {waktu_lokal(ins['mulai'])} terjadi insiden <b>{escape(ins['judul'].lower())}</b> di "
                   f"<b>{escape(l['nama'])}</b> ({escape(l.get('cabang', ''))})."]
        if len(log) > 1:
            kal.append(f"Gejala paling awal tercatat {waktu_lokal(log[0]['waktu'])}: {escape(_kecil(log[0]['pesan']))}, "
                       f"lalu berkembang hingga {escape(_kecil(log[-1]['pesan']))}.")
        elif log:
            kal.append(f"Kejadian tercatat {waktu_lokal(log[0]['waktu'])}: {escape(_kecil(log[0]['pesan']))}.")
        b, ir, dar = r.get("bukti"), r.get("ir"), r.get("darurat")
        pelaku = next((x.get("oleh") for x in r.get("langkah", []) if x.get("selesai") and x.get("oleh")), None)
        if dar:
            kal.append(f"Bukti belum bisa diamankan, sehingga Operator (akun {_akun(dar['petugas'])}) menjalankan isolasi darurat "
                       f"dengan alasan tertulis: \u201c{escape(dar['alasan'])}\u201d.")
        elif b:
            kal.append(f"Atas keputusan Operator (akun {_akun(pelaku or b['petugas'])}), bukti {escape(b['nomor'])} disegel "
                       f"SHA-256 lebih dulu (T+{b['detik']} detik) sebelum satu jalur pun diputus.")
        if ir:
            mttc = r.get("mttc")
            kal.append(f"Aset terisolasi{f' pada T+{mttc} detik' if mttc is not None else ''} dan "
                       f"{escape(ir['nomor'])} ({escape(ir['keparahan'])}) terkirim ke {escape(' dan '.join(ir['kepada']))}.")
        elif not (b or dar):
            kal.append("Belum ada tindakan penahanan; aset menunggu keputusan Operator.")
        else:
            kal.append("Tindakan pemutus sedang berjalan.")
        dampak = dampak_operasional(l, r).replace("Diisolasi: ", "", 1)
        kal.append(f"Dampak operasional: {escape(_kecil(dampak))}")
        paragraf.append(" ".join(kal))
    jml = {s: sum(1 for l in layanan if l.get("status") == s) for s in ("hijau", "kuning", "merah")}
    terbuka = sum(1 for p in peringatan if p.get("kelas") == "terbuka")
    utuh = "utuh" if hasil_audit.get("utuh", True) else "TIDAK utuh"
    awal = "" if paragraf else f"Pemeriksaan rutin pada {waktu_cetak}: tidak ada insiden aktif. "
    paragraf.append(
        f"{awal}Dari {len(layanan)} layanan terpantau, {jml['hijau']} normal, {jml['kuning']} perlu perhatian, dan "
        f"{jml['merah']} dalam insiden. "
        + (f"Tercatat {len(peringatan)} peringatan terbaru, {terbuka} di antaranya masih perlu tindakan; "
           if peringatan else "Tidak ada peringatan terbaru; ")
        + f"temuan aturan deteksi dan AI hanya menaikkan aset ke WASPADA, tidak pernah memutus jaringan "
        f"secara otomatis. Rantai log audit {utuh} ({hasil_audit.get('jumlah', 0)} entri).")
    return [_miring(x) for x in paragraf]


URUTAN_PRIORITAS = ("SEGERA", "HARI INI", "RUTIN")


def tindak_lanjut(layanan: list[dict], rincian: dict, peringatan: list[dict], hasil_audit: dict,
                  titik: dict | None = None) -> list[dict]:
    """v5.4.3 — Tindak lanjut yang disarankan, dihitung dengan aturan tetap dari keadaan yang sama dengan isi laporan.
    Bukan AI dan bukan perintah: setiap butir menyebut dasarnya (data yang memicunya) dan pelaksananya; keputusan
    tetap pada Operator dan pejabat penerima laporan. Tidak ada butir yang menjalankan tindakan apa pun.
    Hasil: daftar {prioritas, tindakan, dasar, pelaksana}, urut SEGERA → HARI INI → RUTIN."""
    dansat = nama_manajemen()[0]
    hasil: list[dict] = []

    def tambah(prioritas: str, tindakan: str, dasar: str, pelaksana: str = "Operator") -> None:
        hasil.append({"prioritas": prioritas, "tindakan": tindakan, "dasar": dasar, "pelaksana": pelaksana})

    if not hasil_audit.get("utuh", True):
        tambah("SEGERA", "Periksa log audit tanpa server (tools/verifikasi_audit.py) dan laporkan ke satuan atasan. "
               "Laporan ini belum boleh menjadi dasar keputusan.",
               f"Rantai log audit TIDAK utuh: {hasil_audit.get('pesan', '')}", f"Operator · {dansat}")

    for l in layanan:
        ins = l.get("insiden")
        if not ins:
            continue
        r = rincian.get("insiden", {}).get(l.get("id"), {})
        b, ir, dar = r.get("bukti"), r.get("ir"), r.get("darurat")
        nama = l["nama"]
        if dar and not b:
            tambah("SEGERA", f"Ambil bukti susulan di {nama}. Pemulihan tetap terkunci sampai bukti susulan aman.",
                   f"Isolasi darurat oleh akun {dar['petugas']} pada {waktu_lokal(dar['waktu'])} tanpa bukti lebih dulu.")
        elif not b and not dar:
            tambah("SEGERA", f"{ISTILAH['langkah_bukti']} di {nama}, lalu putuskan isolasi dengan menahan tombol "
                   "eksekusi.",
                   f"Insiden {ins['judul'].lower()} dimulai {waktu_lokal(ins['mulai'])}; belum ada tindakan penahanan.")
        elif b and not ir and not dar:
            tambah("SEGERA", f"Selesaikan tindakan pemutus playbook di {nama}.",
                   f"Bukti {b['nomor']} sudah disegel; jalur penyerang belum terputus seluruhnya.")
        if ir:
            mttc = r.get("mttc")
            tambah("HARI INI", f"Jalankan prosedur darurat {nama} dan siapkan pemulihan: pastikan ancaman bersih, lalu "
                   "pulihkan dari cadangan yang sudah diuji.",
                   f"Aset terisolasi{f' pada T+{mttc} detik' if mttc is not None else ''}; {ir['nomor']} terkirim.")
            if l.get("jam_sejak_backup", 0) > BATAS_JAM_BACKUP or not l.get("backup_teruji", True):
                tambah("HARI INI", f"Uji pulih cadangan {nama} sebelum pemulihan.",
                       f"Cadangan terakhir {l['jam_sejak_backup']} jam lalu, "
                       f"{'sudah' if l.get('backup_teruji') else 'belum'} diuji pulih.")
        if b:
            tambah("HARI INI", f"Serahkan berita acara bukti {b['nomor']} dan LAPSIT ini ke satuan atasan.",
                   f"Bukti disegel SHA-256 {b['sha256'][:16]}… oleh akun {b['petugas']}; tercatat di "
                   f"{ISTILAH['buku_bukti']}.", f"Operator · mengetahui {dansat}")

    for x in peringatan:
        if x.get("kelas") != "terbuka":
            continue
        if x.get("jenis") == "deteksi":
            usul = x.get("usul_insiden")
            awal = (f"buka insiden bila terbukti (usulan server: {usul['judul']} di {usul['layanan']})" if usul
                    else "tangani melalui playbook bila terbukti")
            tambah("HARI INI", f"Triase temuan {x['id']}: {awal}, atau tutup dengan alasan tertulis.",
                   f"{x['judul']} · {x['status']}.")
        elif x.get("jenis") == "ai":
            tambah("HARI INI", "Periksa lalu lintas aset yang dinilai tidak wajar; pertimbangkan Perketat.",
                   f"{x['judul']} · {x['status']}.")

    for l in layanan:
        if l.get("insiden"):
            continue
        if l.get("jam_sejak_backup", 0) > BATAS_JAM_BACKUP:
            tambah("HARI INI", f"Buat cadangan baru {l['nama']} dan uji pulih.",
                   f"Umur cadangan {l['jam_sejak_backup']} jam (batas {BATAS_JAM_BACKUP} jam).")
        elif not l.get("backup_teruji", True):
            tambah("RUTIN", f"Uji pulih cadangan {l['nama']}.", "Cadangan ada, tetapi belum pernah diuji pulih.")

    if titik and titik.get("aktif") and not titik.get("saksi_no"):
        tambah("RUTIN", "Ekspor Berkas Saksi dan serahkan ke satuan atasan.",
               "Belum ada salinan rantai titik periksa di luar posko.")

    hasil.sort(key=lambda x: URUTAN_PRIORITAS.index(x["prioritas"]))
    return hasil


def _bagian_tindak_lanjut(butir: list[dict], gaya: dict, nomor: int) -> list:
    sel = gaya["kecil"]
    isi = _judul(f"{nomor}. Tindak Lanjut yang Disarankan", gaya)
    if not butir:
        isi.append(Paragraph("Tidak ada tindak lanjut. Lanjutkan pemantauan dan jadwal uji cadangan.", gaya["dasar"]))
    else:
        baris = [["Prioritas", "Tindakan", "Dasar (data yang memicu)", "Pelaksana"]]
        for x in butir:
            baris.append([x["prioritas"], Paragraph(_miring(escape(x["tindakan"])), sel),
                          Paragraph(_tandai_akun(_miring(escape(x["dasar"]))), sel), Paragraph(escape(x["pelaksana"]), sel)])
        tabel = _tabel(baris, [19 * mm, 70 * mm, 57 * mm, 28 * mm])
        for i, x in enumerate(butir, start=1):
            warna = {"SEGERA": WARNA_STATUS["merah"], "HARI INI": WARNA_STATUS["kuning"]}.get(x["prioritas"])
            gaya_sel = [("FONTNAME", (0, i), (0, i), "Helvetica-Bold")]
            if warna is not None:
                gaya_sel.append(("TEXTCOLOR", (0, i), (0, i), warna))
            tabel.setStyle(TableStyle(gaya_sel))
        isi.append(tabel)
    isi.append(Paragraph("Disusun otomatis dengan aturan tetap dari data di laporan ini (app/lapsit.py), bukan oleh AI. "
                         "Saran, bukan perintah: tidak ada tindakan yang dijalankan sistem dari bagian ini.",
                         gaya["catatan"]))
    return isi


def _bagian_drill(drill: list[dict], gaya: dict, nomor: int) -> list:
    """Hasil drill kesiapan (LATIHAN): nilai per komponen beserta sumber angkanya (app/drill.py)."""
    sel = gaya["kecil"]
    isi = _judul(f"{nomor}. {ISTILAH['drill'].upper()} — LATIHAN", gaya)
    isi.append(Paragraph("Simulasi tanggap insiden dengan log sintetis (Perpres 82/2022 Pasal 15). Nilai dihitung dari "
                         "jejak yang tercatat sistem; rumus dan ambangnya terbuka di app/drill.py.", gaya["catatan"]))
    for h in drill:
        isi.append(Paragraph(f"{escape(h['id'])} · {escape(h['judul'])} · Operator (akun {_akun(h['oleh'])}) · "
                             f"selesai {waktu_lokal(h['selesai'])} · <b>{h['nilai']}/100 ({h['huruf']})</b>", gaya["sub"]))
        baris = [["Komponen", "Nilai", "Sumber angka", "Rincian"]]
        for x in h["komponen"]:
            baris.append([Paragraph(escape(x["label"]), sel), f"{x['nilai']}/{x['maks']}",
                          Paragraph(escape(x["sumber"]), sel), Paragraph(escape(x["rincian"]), sel)])
        isi += [_tabel(baris, [38 * mm, 16 * mm, 44 * mm, 76 * mm]),
                Paragraph(f"Kunci jawaban deteksi: {escape(h['catatan_deteksi'])}", gaya["catatan"])]
    return isi


def buat_pdf(layanan: list[dict], hasil_audit: dict, pembuat: str, peringatan: list[dict] | None = None,
             rincian: dict | None = None, titik: dict | None = None, drill: list[dict] | None = None,
             peran: str | None = None) -> bytes:
    gaya = _gaya()
    rincian = rincian or {"insiden": {}, "ioc": []}
    peringatan = peringatan or []
    buffer = BytesIO()
    sekarang = datetime.now(timezone.utc)
    nama_zona, tz = zona()
    waktu = tulis_waktu(sekarang.astimezone(tz), nama_zona, detik=False)
    nomor = f"LAPSIT/NS/{sekarang.astimezone(tz):%Y%m%d-%H%M%S}"
    jumlah_insiden = sum(1 for l in layanan if l.get("insiden"))
    jenis = f"Laporan insiden ({jumlah_insiden} aktif)" if jumlah_insiden else "Laporan rutin"
    dok = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=39 * mm, bottomMargin=16 * mm,
                            title=f"LAPSIT Nusantara Shield {nomor}", author="Nusantara Shield")
    isi = [Paragraph(f"Dibuat oleh: <b>{escape(ISTILAH.get(f'peran_{peran}', 'Akun'))}</b> (akun {_akun(pembuat)}) · "
                     f"zona waktu {nama_zona} "
                     f"(UTC+{ZONA_WAKTU[nama_zona]})", gaya["dasar"]),
           Paragraph("Dokumen latihan. Seluruh data sintetis, tidak memuat data pribadi; perintah ke perangkat "
                     "jaringan masih simulasi.", gaya["catatan"])]

    # 1. Ringkasan eksekutif
    isi += _judul("1. Ringkasan Eksekutif", gaya)
    isi.append(_kotak([Paragraph(p, gaya["dasar"].clone("paragraf", spaceAfter=4)) for p in
                       ringkasan_eksekutif(layanan, rincian, peringatan, hasil_audit, waktu)]))

    # 2. Status layanan dan dampak operasional
    isi += _judul("2. Status Layanan dan Dampak Operasional", gaya)
    sel = gaya["kecil"]
    baris = [["Layanan", "Status", "Cadangan", "Dampak operasional (perkiraan)"]]
    for l in layanan:
        baris.append([Paragraph(escape(l["nama"]), sel), l["status"].upper(),
                      Paragraph(f"{l['jam_sejak_backup']} jam lalu · {'diuji' if l['backup_teruji'] else 'belum diuji'}",
                                sel),
                      Paragraph(_miring(escape(dampak_operasional(l, rincian["insiden"].get(l.get("id"))))), sel)])
    tabel = _tabel(baris, [52 * mm, 17 * mm, 25 * mm, 80 * mm])
    for i, l in enumerate(layanan, start=1):
        tabel.setStyle(TableStyle([("TEXTCOLOR", (1, i), (1, i), WARNA_STATUS[l["status"]]),
                                   ("FONTNAME", (1, i), (1, i), "Helvetica-Bold")]))
    isi += [tabel, Paragraph("Dampak adalah perkiraan menurut profil misi layanan contoh, bukan hasil pengukuran.",
                             gaya["catatan"])]

    # 3. Insiden aktif: kronologi dan tindakan playbook bercap waktu dan beraktor
    isi += _judul("3. Insiden Aktif dan Tindakan", gaya)
    insiden = [l for l in layanan if l.get("insiden")]
    if not insiden:
        isi.append(Paragraph("Tidak ada insiden aktif.", gaya["dasar"]))
    for l in insiden:
        ins, r = l["insiden"], rincian["insiden"].get(l.get("id"), {})
        tm = ins.get("temuan")
        attck = ringkas_mitre(tm["aturan"] if tm else ins.get("skenario"))
        isi.append(Paragraph(_miring(f"{escape(l['nama'])} — {escape(ins['judul'])}"), gaya["sub"]))
        isi.append(Paragraph(f"Dimulai {waktu_lokal(ins['mulai'])}"
                             + (f" · Teknik MITRE ATT&amp;CK: {_teknik(escape(attck))}" if attck else ""), gaya["kecil"]))
        if tm:
            isi.append(Paragraph(
                f"Asal: temuan log asli {escape(tm['id'])} · aturan {escape(tm['nama'])} · sumber {escape(tm['sumber'])} · "
                f"berkas {escape(tm['berkas'])}" + (f" ({int(tm['baris'])} baris)" if tm.get("baris") else "")
                + (f" · SHA-256 berkas <font face='Courier'>{escape(tm['sha256_berkas'])}</font>"
                   if tm.get("sha256_berkas") else "") + ". Aset terdampak diambil dari temuan, bukan templat latihan.",
                gaya["kecil"]))
        if ins.get("log_peringatan"):
            baris = [["Waktu", "Tingkat", "Kronologi gejala"]]
            for g in ins["log_peringatan"]:
                baris.append([waktu_lokal(g["waktu"], tabel=True), g["tingkat"].upper(),
                              Paragraph(_miring(escape(g["pesan"])), sel)])
            isi += [Spacer(1, 3), _tabel(baris, [40 * mm, 18 * mm, 116 * mm])]
        baris = [["Status", "Langkah penanganan", "Waktu eksekusi", "Sejak awal", "Aktor"]]
        ir = r.get("ir")
        for x in r.get("langkah", [{"teks": tk, "selesai": s} for tk, s in zip(ins["langkah"], ins["langkah_selesai"])]):
            judul = x["teks"].split(":")[0]
            w, detik, aktor = x.get("waktu"), x.get("detik"), _aktor(x) if x.get("metode") else "—"
            if x["selesai"] and not w and ir and x["teks"].startswith("LAPOR"):
                w, detik, aktor = ir["waktu"], ir["detik"], "sistem · otomatis setelah pemutusan"
            status = "SELESAI" if x["selesai"] else "ANTRE" if x.get("antre") else "BELUM"
            baris.append([status, Paragraph(escape(judul), sel), waktu_lokal(w, tabel=True) if x["selesai"] else "—",
                          f"T+{detik} dtk" if x["selesai"] and detik is not None else "—", Paragraph(aktor if x.get("metode") else escape(aktor), sel)])
        tabel_playbook = _tabel(baris, [16 * mm, 39 * mm, 39 * mm, 19 * mm, 61 * mm])
        metrik = []
        b, dar = r.get("bukti"), r.get("darurat")
        if b:
            metrik.append(f"<b>Bukti</b> {escape(b['nomor'])} · SHA-256 <font face='Courier' size='7'>{escape(b['sha256'])}"
                          f"</font> · {len(b.get('barang', []))} berkas · disegel oleh akun {_akun(b['petugas'])} "
                          f"pada {waktu_lokal(b['waktu'])}")
        if dar:
            metrik.append(f"<b>Isolasi darurat</b> oleh akun {_akun(dar['petugas'])} pada {waktu_lokal(dar['waktu'])}; "
                          f"alasan: {escape(dar['alasan'])}")
        if r.get("mttc") is not None:
            metrik.append(f"<b>Waktu penahanan (MTTC)</b>: {r['mttc']} detik sejak insiden dimulai hingga jalur "
                          f"penyerang terputus. Jeda antartindakan pemutus otomatis {_koma(r.get('jeda_runbook', 1.2))} "
                          f"detik (simulasi purwarupa, bukan hasil ukur perangkat).")
        if ir:
            metrik.append(f"<b>{escape(ir['nomor'])}</b> ({escape(ir['keparahan'])}) terkirim ke "
                          f"{escape(' dan '.join(ir['kepada']))} pada {waktu_lokal(ir['waktu'])} (simulasi: tidak ada "
                          f"pesan yang keluar dari server).")
        isi.append(KeepTogether([Spacer(1, 4), tabel_playbook, Spacer(1, 3)] + [Paragraph(_miring(m), sel) for m in metrik]))

    # 4. Indikator kompromi
    isi += _judul("4. Indikator Kompromi (IoC)", gaya)
    if not rincian["ioc"]:
        isi.append(Paragraph("Tidak ada indikator kompromi aktif.", gaya["dasar"]))
    else:
        baris = [["Tipe", "Nilai", "Rujukan", "Aset/konteks", "Status"]]
        for x in rincian["ioc"]:
            baris.append([Paragraph(_miring(escape(x["tipe"])), sel),
                          Paragraph(f"<font face='Courier'>{_miring(escape(x['nilai']))}</font>", sel),
                          Paragraph(escape(x["rujukan"]), sel), Paragraph(_miring(escape(x["konteks"])), sel),
                          Paragraph(_miring(escape(x["status"])), sel)])
        isi += [_tabel(baris, [36 * mm, 44 * mm, 22 * mm, 34 * mm, 38 * mm]),
                Paragraph("Alamat memakai blok dokumentasi RFC 5737 (sintetis). Sumber temuan aturan deteksi tidak "
                          "diblokir otomatis: pemutusan hanya melalui keputusan Operator.", gaya["catatan"])]

    # 5. Peringatan terbaru
    isi += _judul("5. Peringatan Terbaru", gaya)
    if not peringatan:
        isi.append(Paragraph("Tidak ada peringatan.", gaya["dasar"]))
    else:
        baris = [["Keparahan", "Peringatan", "Teknik ATT&CK", "Status"]]
        for p in peringatan:
            teks = _miring(escape(p["judul"])) + (f"<br/><i>{escape(p['sumber_data'])}</i>" if p.get("sumber_data") else "")
            baris.append([p["keparahan"].upper(), Paragraph(teks, sel),
                          Paragraph(escape(", ".join(m["id"] for m in p.get("mitre", [])) or "—"), sel),
                          Paragraph(_akun_status(_miring(escape(p["status"]))), sel)])
        isi += [_tabel(baris, [20 * mm, 84 * mm, 26 * mm, 44 * mm]),
                Paragraph("Teknik MITRE ATT&amp;CK® dipetakan oleh tim sendiri sebagai rujukan, bukan sertifikasi. "
                          "MITRE ATT&amp;CK® adalah merek dagang The MITRE Corporation.", gaya["catatan"])]

    isi += _bagian_tindak_lanjut(tindak_lanjut(layanan, rincian, peringatan, hasil_audit, titik), gaya, 6)

    nomor_bagian = 7
    if drill:
        isi += _bagian_drill(drill, gaya, nomor_bagian)
        nomor_bagian += 1

    # Integritas log audit
    isi += _judul(f"{nomor_bagian}. Integritas Log Audit", gaya)
    isi.append(Paragraph(escape(hasil_audit["pesan"]) + f" ({hasil_audit['jumlah']} entri).", gaya["dasar"]))
    if hasil_audit.get("hash_terakhir"):
        isi.append(Paragraph("Sidik jari terakhir (HMAC-SHA256): <font face='Courier' size='7'>"
                             f"{escape(hasil_audit['hash_terakhir'])}</font>", gaya["dasar"]))
    if titik and titik.get("aktif") and titik.get("no"):
        isi.append(Paragraph(
            f"Titik periksa #{titik['no']} (Ed25519) dibuat saat laporan ini dicetak. Sidik jari kunci akar: "
            f"<font face='Courier' size='7'>{escape(titik['sidik_jari_akar'])}</font>", gaya["dasar"]))
        if titik.get("saksi_no"):
            try:
                nz, tz_ = zona()
                kapan = f" ({tulis_waktu(datetime.fromisoformat(titik['saksi_waktu']).astimezone(tz_), nz, detik=False)})"
            except (TypeError, ValueError):
                kapan = ""
            isi.append(Paragraph(
                f"Berkas Saksi terakhir diekspor pada titik periksa #{int(titik['saksi_no'])}{escape(kapan)}. Riwayat sampai titik itu terlindungi selama satuan atasan "
                "menyimpan berkasnya.", gaya["dasar"]))
        else:
            isi.append(Paragraph(
                "Belum ada Berkas Saksi yang diekspor. Tanpa salinan di luar posko, penggulungan mundur riwayat hanya "
                "tertangkap melalui nomor titik periksa di LAPSIT ini. Ekspor Saksi di <i>tab</i> Audit &amp; LAPSIT lalu serahkan ke "
                "satuan atasan.", gaya["catatan"]))
    elif titik and titik.get("galat") and not titik.get("demo"):
        isi.append(Paragraph(escape(titik["galat"]), gaya["catatan"]))
    isi += [Spacer(1, 4), _kotak([Paragraph(
        "<b>Cara memverifikasi.</b> Sidik jari di atas adalah HMAC-SHA256 entri terakhir log audit saat laporan "
        "ini dicetak. Cocokkan dengan <b>Verifikasi rantai</b> (<i>tab</i> Audit &amp; LAPSIT atau "
        "<font face='Courier'>GET /api/audit/verifikasi</font>), atau tanpa <i>server</i>: "
        "<font face='Courier'>python3 tools/verifikasi_audit.py --cocokkan &lt;sidik jari&gt;</font>. "
        + ("Titik periksa diperiksa tanpa kunci rahasia: <font face='Courier'>python3 tools/verifikasi_titik_periksa.py "
           f"--akar &lt;sidik jari akar&gt; --minimal-titik {int(titik.get('no') or 0)}</font> (nomor ini menangkap riwayat yang "
           "digulung mundur). Bila satuan atasan memegang Berkas Saksi, ganti opsi terakhir dengan "
           "<font face='Courier'>--saksi &lt;berkas saksi&gt;</font>. " if titik and titik.get("aktif") else "")
        + f"Telusuri nomor bukti di {escape(ISTILAH['buku_bukti'])}. Sidik jari ini menjamin keutuhan log audit, bukan "
        f"keutuhan berkas PDF; salinan yang diteruskan wajib bertanda tangan di bagian {escape(ISTILAH['ttd_judul'])}.",
        sel)],
        latar=colors.white)]

    # Blok tanda tangan
    isi += [KeepTogether([*_judul(f"{nomor_bagian + 1}. {ISTILAH['ttd_judul']}", gaya), _blok_pengesahan(gaya)])]
    kop = _penggambar_kop(nomor, waktu, jenis)
    dok.build(isi, canvasmaker=lambda *a, **kw: _KanvasBernomor(*a, kop=kop, **kw))
    return buffer.getvalue()
