# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
impor_log.py — Membaca berkas log ASLI yang dibawa Operator (luring), lalu mengubahnya menjadi peristiwa mentah
untuk mesin deteksi aturan (app/deteksi.py). Tidak ada aturan baru di sini: aturan yang sama menilai log latihan
maupun log asli.

Analogi: petugas jaga menyerahkan buku tamu pos lain. Kita tidak menulis ulang bukunya; kita hanya menyalin baris
yang relevan (siapa, dari mana, ke mana, kapan) ke format buku tamu kita, lalu aturan yang sama membacanya.

Format yang dikenali (dipilih otomatis per baris):
1. Log autentikasi OpenSSH (auth.log / secure / journal): "Failed password ... from IP" dan "Accepted ... from IP".
2. Log firewall UFW/iptables (kern.log / ufw.log): baris berisi SRC=, DST=, dan DPT=.
3. CSV berkepala: waktu, jenis (login | koneksi | koneksi_ot | modbus), sumber, lalu kolom sesuai jenis.
4. Keluaran sensor yang mungkin sudah dimiliki satuan, JSON per baris (atau satu larik JSON):
   - Wazuh alerts.json: peringatan bergrup authentication_failed / invalid_login (gagal) dan authentication_success
     (berhasil) → upaya login dari data.srcip. Peringatan agregat Wazuh (mis. 5763 "brute force") TIDAK dihitung:
     yang menilai rentetan adalah aturan kita sendiri, dengan ambang terbuka.
   - Suricata eve.json: event flow/alert/netflow → koneksi (ke port 502 aset OT → koneksi_ot); event modbus →
     perintah Modbus (function_raw). Jam perintah diambil dari stempel waktu sensor, jadi jendela pemeliharaan
     dinilai menurut jam di lokasi sensor, bukan zona waktu server.
   Modul ini hanya MEMBACA berkas keluaran sensor; ia tidak memasang, mengatur, atau menghubungi sensor.

Prinsip keamanan dan privasi:
- Sepenuhnya defensif dan luring: modul ini hanya membaca teks yang diserahkan; ia tidak memindai atau menghubungi apa pun.
- Validasi ketat di batas kepercayaan: alamat IP harus sah, port 1–65535, jam 0–23; baris yang tidak dikenali dilewati
  dan dihitung, bukan ditebak.
- Nama akun dalam log TIDAK disimpan (tidak dibutuhkan aturan mana pun). Isi mentah log tidak masuk log audit.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from datetime import datetime, timezone

MAKS_BARIS = 50_000
MAKS_PERISTIWA = 20_000

_BULAN = {b: i for i, b in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}
_SYSLOG = re.compile(r"^(?P<bln>[A-Z][a-z]{2})\s+(?P<hari>\d{1,2}) (?P<j>\d\d):(?P<m>\d\d):(?P<d>\d\d) \S+ (?P<isi>.*)$")
_ISO = re.compile(r"^(?P<iso>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?) \S+ (?P<isi>.*)$")
_SSH_GAGAL = re.compile(r"sshd(?:\[\d+\])?: Failed (?:password|publickey|none|keyboard-interactive/pam) for "
                        r"(?:invalid user )?\S+ from (?P<ip>[0-9A-Fa-f:.]+) port \d+")
_SSH_MASUK = re.compile(r"sshd(?:\[\d+\])?: Accepted \S+ for \S+ from (?P<ip>[0-9A-Fa-f:.]+) port \d+")
_FW = re.compile(r"\bSRC=(?P<src>[0-9A-Fa-f:.]+)\b.*\bDST=(?P<dst>[0-9A-Fa-f:.]+)\b.*\bDPT=(?P<dpt>\d+)\b")
JENIS_CSV = ("login", "koneksi", "koneksi_ot", "modbus")
PORT_OT = {502}                                    # Modbus/TCP: koneksi ke aset di port ini = koneksi ke zona kendali
GRUP_WAZUH_GAGAL = {"authentication_failed", "invalid_login"}
GRUP_WAZUH_BERHASIL = {"authentication_success"}
EVENT_SURICATA_KONEKSI = {"flow", "alert", "netflow"}


class GalatImpor(ValueError):
    """Berkas tidak bisa dipakai sama sekali (format tidak dikenali, terlalu besar, kosong)."""


def _ip(teks: str) -> str | None:
    try:
        return str(ipaddress.ip_address(teks.strip()))
    except ValueError:
        return None


def _waktu_syslog(m: re.Match, tahun: int) -> float | None:
    try:
        return datetime(tahun, _BULAN[m["bln"]], int(m["hari"]), int(m["j"]), int(m["m"]), int(m["d"])).timestamp()
    except (KeyError, ValueError):
        return None


def _dt_iso(teks) -> datetime | None:
    if not isinstance(teks, str):
        return None
    try:
        return datetime.fromisoformat(teks.strip().replace("Z", "+00:00"))   # juga +0700 (Wazuh, Suricata)
    except ValueError:
        return None


def _waktu_iso(teks: str) -> float | None:
    teks = teks.strip()
    if re.fullmatch(r"\d{9,11}(?:\.\d+)?", teks):                 # detik epoch
        return float(teks)
    try:
        return datetime.fromisoformat(teks.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _jam_lokal(t: float) -> int:
    return datetime.fromtimestamp(t).hour


def _aset(teks: str | None, aset_by_ip: dict[str, str], aset_dikenal: set[str]) -> str | None:
    if not teks:
        return None
    teks = teks.strip()
    if teks in aset_dikenal:
        return teks
    ip = _ip(teks)
    return aset_by_ip.get(ip) if ip else None


def _baris_teks(baris: str, tahun: int, aset_ssh: str, port_aset: dict[tuple[str, int], str]) -> tuple[float, dict] | None:
    m = _SYSLOG.match(baris)
    t = _waktu_syslog(m, tahun) if m else None
    if not m:
        m = _ISO.match(baris)
        t = _waktu_iso(m["iso"]) if m else None
    if not m or t is None:
        return None
    isi = m["isi"]
    for pola, berhasil in ((_SSH_GAGAL, False), (_SSH_MASUK, True)):
        k = pola.search(isi)
        if k and (ip := _ip(k["ip"])):
            return t, {"jenis": "login", "sumber": ip, "aset": aset_ssh, "berhasil": berhasil}
    k = _FW.search(isi)
    if k and (src := _ip(k["src"])) and (dst := _ip(k["dst"])) and 0 < int(k["dpt"]) < 65536:
        port = int(k["dpt"])
        return t, {"jenis": "koneksi", "sumber": src, "ip": dst, "port": port, "aset": port_aset.get((dst, port))}
    return None


def _baris_csv(r: dict, aset_by_ip: dict[str, str], aset_dikenal: set[str],
               port_aset: dict[tuple[str, int], str]) -> tuple[float, dict] | None:
    jenis, sumber = (r.get("jenis") or "").strip().lower(), _ip(r.get("sumber") or "")
    t = _waktu_iso(r.get("waktu") or "")
    if jenis not in JENIS_CSV or not sumber or t is None:
        return None
    try:
        if jenis == "login":
            aset = _aset(r.get("aset"), aset_by_ip, aset_dikenal)
            berhasil = (r.get("berhasil") or "").strip().lower()
            if not aset or berhasil not in ("ya", "tidak", "true", "false", "1", "0"):
                return None
            return t, {"jenis": "login", "sumber": sumber, "aset": aset, "berhasil": berhasil in ("ya", "true", "1")}
        if jenis == "koneksi":
            ip, port = _ip(r.get("ip") or ""), int(r.get("port") or 0)
            if not ip or not 0 < port < 65536:
                return None
            return t, {"jenis": "koneksi", "sumber": sumber, "ip": ip, "port": port, "aset": port_aset.get((ip, port))}
        aset = _aset(r.get("aset"), aset_by_ip, aset_dikenal)
        if not aset:
            return None
        if jenis == "koneksi_ot":
            return t, {"jenis": "koneksi_ot", "sumber": sumber, "aset": aset}
        fungsi = int(r.get("fungsi") or 0)
        jam = int(r["jam"]) if (r.get("jam") or "").strip() else _jam_lokal(t)
        if not 0 < fungsi < 128 or not 0 <= jam <= 23:
            return None
        return t, {"jenis": "modbus", "sumber": sumber, "aset": aset, "fungsi": fungsi, "jam": jam}
    except (TypeError, ValueError):
        return None


def _port(nilai) -> int | None:
    try:
        port = int(nilai)
    except (TypeError, ValueError):
        return None
    return port if 0 < port < 65536 else None


def _baris_json(o, aset_ssh: str, aset_by_ip: dict[str, str],
                port_aset: dict[tuple[str, int], str]) -> tuple[str, float, dict] | None:
    """Satu objek JSON keluaran sensor → (sumber, waktu, peristiwa mentah), atau None bila bukan yang dinilai aturan."""
    if not isinstance(o, dict):
        return None
    d = _dt_iso(o.get("timestamp"))
    if d is None:
        return None
    t = d.timestamp()
    if isinstance(o.get("rule"), dict) and "agent" in o:                      # Wazuh
        grup = set(o["rule"].get("groups") or [])
        berhasil = True if grup & GRUP_WAZUH_BERHASIL else False if grup & GRUP_WAZUH_GAGAL else None
        data = o.get("data") if isinstance(o.get("data"), dict) else {}
        sumber = _ip(str(data.get("srcip", "")))
        if berhasil is None or not sumber:
            return None
        agen = o.get("agent") if isinstance(o.get("agent"), dict) else {}
        aset = aset_by_ip.get(_ip(str(agen.get("ip", ""))) or "") or aset_ssh
        return "wazuh", t, {"jenis": "login", "sumber": sumber, "aset": aset, "berhasil": berhasil}
    jenis = o.get("event_type")
    if not isinstance(jenis, str):
        return None
    sumber, tujuan, port = _ip(str(o.get("src_ip", ""))), _ip(str(o.get("dest_ip", ""))), _port(o.get("dest_port"))
    if not sumber or not tujuan or port is None:
        return None
    aset = port_aset.get((tujuan, port))
    if jenis in EVENT_SURICATA_KONEKSI:                                        # Suricata: satu aliran = satu koneksi
        if aset and port in PORT_OT:
            return "suricata", t, {"jenis": "koneksi_ot", "sumber": sumber, "aset": aset}
        return "suricata", t, {"jenis": "koneksi", "sumber": sumber, "ip": tujuan, "port": port, "aset": aset}
    if jenis == "modbus" and aset and port in PORT_OT:
        req = (o.get("modbus") or {}).get("request") if isinstance(o.get("modbus"), dict) else None
        fungsi = req.get("function_raw") if isinstance(req, dict) else None
        if not isinstance(fungsi, int) or isinstance(fungsi, bool) or not 0 < fungsi < 128:
            return None
        jam = d.hour if d.tzinfo else _jam_lokal(t)                           # jam di lokasi sensor
        return "suricata", t, {"jenis": "modbus", "sumber": sumber, "aset": aset, "fungsi": fungsi, "jam": jam}
    return None


def _objek_json(isi: str, baris: list[str]) -> list | None:
    """JSON per baris (alerts.json, eve.json) atau satu larik JSON (ekspor). None bila bukan JSON."""
    awal = isi.lstrip()[:1]
    if awal == "[":
        try:
            data = json.loads(isi)
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, list) else None
    if awal != "{":
        return None
    hasil = []
    for b in baris:
        if not b.strip():
            continue
        try:
            hasil.append(json.loads(b))
        except json.JSONDecodeError:
            hasil.append(None)                                                 # baris rusak: dihitung, tidak ditebak
    return hasil


def baca(isi: str, simpul: list[dict], aset_ssh: str = "ssh", tahun: int | None = None) -> tuple[list[tuple[float, dict]], dict]:
    """Teks berkas → ([(waktu epoch, peristiwa mentah)] berurutan waktu, ringkasan). GalatImpor bila tak ada yang dikenali."""
    baris = isi.splitlines()
    if len(baris) > MAKS_BARIS:
        raise GalatImpor(f"Berkas terlalu panjang (lebih dari {MAKS_BARIS:,} baris)".replace(",", "."))
    tahun = tahun or datetime.now(timezone.utc).year
    aset_by_ip = {s["ip"]: s["id"] for s in simpul if s.get("port")}
    aset_dikenal = set(aset_by_ip.values())
    port_aset = {(s["ip"], s["port"]): s["id"] for s in simpul if s.get("port")}
    kepala = baris[0].strip().lower().replace(" ", "") if baris else ""
    hasil: list[tuple[float, dict]] = []
    objek = _objek_json(isi, baris)
    if objek is not None:
        if len(objek) > MAKS_BARIS:
            raise GalatImpor(f"Berkas terlalu panjang (lebih dari {MAKS_BARIS:,} peristiwa)".replace(",", "."))
        jumlah, asal = len(objek), set()
        for o in objek:
            if (x := _baris_json(o, aset_ssh, aset_by_ip, port_aset)) is not None:
                asal.add(x[0])
                hasil.append((x[1], x[2]))
        format_ = " + ".join(n for k, n in (("wazuh", "Wazuh alerts.json"), ("suricata", "Suricata eve.json")) if k in asal)
        format_ = format_.replace("alerts.json + Suricata eve.json", "+ Suricata") if len(asal) == 2 else format_
    elif kepala.startswith("waktu,") or ",jenis," in kepala:
        format_ = "csv"
        pembaca = csv.DictReader(io.StringIO(isi))
        pembaca.fieldnames = [f.strip().lower() for f in (pembaca.fieldnames or [])]
        jumlah = 0
        for r in pembaca:
            jumlah += 1
            if (x := _baris_csv(r, aset_by_ip, aset_dikenal, port_aset)) is not None:
                hasil.append(x)
    else:
        format_, jumlah = "teks", 0
        for b in baris:
            if not b.strip():
                continue
            jumlah += 1
            if (x := _baris_teks(b, tahun, aset_ssh, port_aset)) is not None:
                hasil.append(x)
        if hasil:
            jenis = {ev["jenis"] for _, ev in hasil}
            format_ = "auth.log (OpenSSH)" if jenis == {"login"} else "firewall (UFW/iptables)" if jenis == {"koneksi"} \
                else "auth.log + firewall"
    if not hasil:
        raise GalatImpor("Tidak ada baris yang dikenali. Format yang didukung: auth.log OpenSSH, log firewall "
                         "UFW/iptables (SRC=, DST=, DPT=), CSV berkepala waktu,jenis,sumber,…, Wazuh alerts.json, "
                         "atau Suricata eve.json")
    if len(hasil) > MAKS_PERISTIWA:
        raise GalatImpor(f"Terlalu banyak peristiwa (lebih dari {MAKS_PERISTIWA:,}); pecah berkasnya".replace(",", "."))
    hasil.sort(key=lambda x: x[0])
    return hasil, {"format": format_, "baris": jumlah, "dikenali": len(hasil), "diabaikan": jumlah - len(hasil),
                   "rentang_detik": round(hasil[-1][0] - hasil[0][0])}
