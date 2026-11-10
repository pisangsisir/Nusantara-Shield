#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
#
# pasang.sh — pemasang Nusantara Shield untuk Ubuntu 24.04 LTS x86_64 TANPA internet.
#
# Urutan kerja (berhenti di langkah pertama yang gagal; sebelum langkah 5 tidak ada yang diubah di sistem):
#   1. Prasyarat   : root, Ubuntu 24.04, x86_64, /usr/bin/python3.12, OpenSSL 3, sha256sum.        (kode 20)
#   2. Keaslian    : sidik jari kunci publik = yang tertanam di skrip ini; tanda tangan Ed25519 atas
#                    SHA256SUMS sah; setiap berkas paket cocok dengan SHA256SUMS.                  (kode 10)
#   3. Isi payload : payload cocok dengan manifest; setiap anggota tar diperiksa TANPA diekstrak
#                    (tanpa jalur absolut, tanpa "..", tanpa tautan/perangkat, harus tercatat).     (kode 11)
#   4. Ekstraksi   : ke folder sementara dengan filter "data" Python, lalu SHA-256 dan ukuran SETIAP
#                    berkas dicocokkan dengan manifest; berkas lebih atau kurang = batal.           (kode 12)
#   5. Lingkungan  : venv dari python3.12 bawaan + pip --no-index --require-hashes; uji asap.       (kode 13)
#   6. Pasang      : pengguna sistem nshield, /etc/nusantara-shield/env (dibuat sekali), layanan
#                    systemd, tautan "kini" diganti secara atomik, cek /api/health; gagal = kembali
#                    ke rilis sebelumnya.                                                           (kode 14)
# Kode 2 = argumen salah. Kode 0 = berhasil.
#
# Batas yang jujur: skrip ini tidak bisa membuktikan keaslian DIRINYA SENDIRI (bila paket dipalsukan,
# skrip pun bisa ikut dipalsukan). Karena itu operator memeriksa sidik jari paket, sidik jari kunci, dan
# tanda tangan secara manual dulu (lihat BACA-SAYA.txt), baru menjalankan skrip ini.

set -u
umask 022

VERSI="@@VERSI@@"
SIDIK_JARI_KUNCI="@@SIDIK_JARI_KUNCI@@"
PY=/usr/bin/python3.12
PENGGUNA=nshield
PORT_BAWAAN=8000

info()  { printf '  %s\n' "$*"; }
judul() { printf '\n[%s] %s\n' "$1" "$2"; }
gagal() {
	kode=$1; shift
	printf '\nGAGAL (kode %s): %s\n' "$kode" "$*" >&2
	exit "$kode"
}

bantuan() {
	cat <<EOF
Pemakaian: sudo sh pasang.sh [pilihan]

  (tanpa pilihan)       verifikasi paket lalu pasang/naikkan versi Nusantara Shield $VERSI
  --uji                 setelah memasang pustaka, jalankan seluruh uji otomatis (pytest) dulu
  --host-diizinkan H    nama host/IP tambahan untuk NS_ALLOWED_HOSTS (hanya saat env pertama dibuat)
  --izinkan-turun       izinkan memasang versi yang LEBIH LAMA dari versi aktif
  --tanpa-systemd       pasang berkas saja, tanpa mendaftarkan/menyalakan layanan systemd
  --kembali             kembali ke rilis sebelumnya (tanpa memasang paket ini)
  --hapus               hapus program dan layanan; /etc/nusantara-shield dan data dipertahankan
  --awalan DIR          mode uji: pasang di bawah DIR, tanpa root, tanpa useradd/chown/systemctl
  --tanpa-venv          (hanya bersama --awalan) lewati pembuatan venv dan uji asap
  --bantuan             tampilkan bantuan ini
EOF
}

# ------------------------------------------------------------------ argumen
AWALAN=""; TANPA_SYSTEMD=0; TANPA_VENV=0; IZINKAN_TURUN=0; UJI=0; MODE=pasang; HOST_TAMBAHAN=""
while [ $# -gt 0 ]; do
	case "$1" in
		--awalan)          [ $# -ge 2 ] || { bantuan >&2; exit 2; }; AWALAN=$2; shift ;;
		--tanpa-systemd)   TANPA_SYSTEMD=1 ;;
		--tanpa-venv)      TANPA_VENV=1 ;;
		--izinkan-turun)   IZINKAN_TURUN=1 ;;
		--uji)             UJI=1 ;;
		--hapus)           MODE=hapus ;;
		--kembali)         MODE=kembali ;;
		--host-diizinkan)  [ $# -ge 2 ] || { bantuan >&2; exit 2; }; HOST_TAMBAHAN=$2; shift ;;
		--bantuan|-h|--help) bantuan; exit 0 ;;
		*) printf 'Pilihan tidak dikenal: %s\n\n' "$1" >&2; bantuan >&2; exit 2 ;;
	esac
	shift
done
case "$VERSI$SIDIK_JARI_KUNCI" in
	*@@*) gagal 2 "ini templat installer/pasang.sh dari repo, bukan paket rilis. Jalankan pasang.sh dari paket hasil tools/kemas_installer.py." ;;
esac
if [ "$TANPA_VENV" = 1 ] && [ -z "$AWALAN" ]; then
	gagal 2 "--tanpa-venv hanya untuk mode uji (--awalan); pemasangan sungguhan selalu membuat venv dan uji asap"
fi
case "$HOST_TAMBAHAN" in
	*[!A-Za-z0-9.,:_-]*) gagal 2 "--host-diizinkan hanya boleh berisi huruf, angka, titik, koma, titik dua, - dan _" ;;
esac

if [ -n "$AWALAN" ]; then
	mkdir -p "$AWALAN" || gagal 2 "folder --awalan tidak bisa dibuat"
	ROOT=$(CDPATH='' cd -- "$AWALAN" && pwd -P)
	TANPA_SYSTEMD=1
else
	ROOT=""
fi
OPT=$ROOT/opt/nusantara-shield
ETC=$ROOT/etc/nusantara-shield
VARLIB=$ROOT/var/lib/nusantara-shield
VARLOG=$ROOT/var/log/nusantara-shield
UNIT=$ROOT/etc/systemd/system/nusantara-shield.service
PEMBUNGKUS=$ROOT/usr/local/bin/ns-verifikasi-audit
PAKET=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)

# ------------------------------------------------------------------ 1. prasyarat
judul 1/6 "Memeriksa prasyarat sistem (belum ada yang diubah)"
belum_diubah="Pemasangan dibatalkan; tidak ada yang diubah di sistem ini."
if [ -z "$AWALAN" ] && [ "$(id -u)" != 0 ]; then
	gagal 20 "jalankan sebagai root: sudo sh pasang.sh. $belum_diubah"
fi
OS_RELEASE=/etc/os-release
if [ -n "$AWALAN" ] && [ -n "${NS_PASANG_OS_RELEASE:-}" ]; then
	OS_RELEASE=$NS_PASANG_OS_RELEASE          # hanya mode uji
fi
nilai_os() { sed -n "s/^$1=//p" "$OS_RELEASE" 2>/dev/null | head -n 1 | tr -d '"'; }
OS_ID=$(nilai_os ID); OS_VERSI=$(nilai_os VERSION_ID)
if [ "$OS_ID" != ubuntu ] || [ "$OS_VERSI" != 24.04 ]; then
	gagal 20 "paket ini khusus Ubuntu 24.04 LTS; sistem ini ${OS_ID:-tidak dikenal} ${OS_VERSI:-?}. $belum_diubah"
fi
[ "$(uname -m)" = x86_64 ] || gagal 20 "paket ini khusus x86_64; mesin ini $(uname -m). $belum_diubah"
if [ ! -x "$PY" ]; then
	gagal 20 "Python 3.12 bawaan Ubuntu 24.04 tidak ditemukan di $PY. Paket ini sengaja tidak membawa Python.
  Ubuntu 24.04 Server standar sudah memilikinya; bila terhapus, pasang kembali paket python3.12 dari media
  instalasi atau cermin repositori lokal Ubuntu, lalu ulangi. $belum_diubah"
fi
"$PY" -I -c 'import sys, tarfile, venv; assert sys.version_info[:2] == (3, 12); assert hasattr(tarfile, "data_filter")' \
	2>/dev/null || gagal 20 "$PY bukan Python 3.12 lengkap (butuh modul venv dan tarfile.data_filter). $belum_diubah"
command -v openssl >/dev/null 2>&1 || gagal 20 "openssl tidak ditemukan. $belum_diubah"
case "$(openssl version 2>/dev/null)" in
	"OpenSSL 3"*) ;;
	*) gagal 20 "butuh OpenSSL 3 (bawaan Ubuntu 24.04); ditemukan: $(openssl version 2>/dev/null). $belum_diubah" ;;
esac
command -v sha256sum >/dev/null 2>&1 || gagal 20 "sha256sum tidak ditemukan. $belum_diubah"
if [ -z "$AWALAN" ]; then
	for alat in useradd getent install chown; do
		command -v "$alat" >/dev/null 2>&1 || gagal 20 "$alat tidak ditemukan. $belum_diubah"
	done
	if [ "$TANPA_SYSTEMD" = 0 ]; then
		command -v systemctl >/dev/null 2>&1 || gagal 20 "systemctl tidak ditemukan (pakai --tanpa-systemd bila memang tanpa systemd). $belum_diubah"
	fi
fi
info "Ubuntu $OS_VERSI · $(uname -m) · $("$PY" -c 'import sys; print("Python", sys.version.split()[0])') · $(openssl version | cut -d' ' -f1-2)"

# ------------------------------------------------------------------ mode hapus / kembali
uji_kesehatan() {   # $1 = port; mengembalikan 0 bila /api/health menjawab {"status": "ok"}
	"$PY" -I - "$1" <<'PY'
import json, sys, time, urllib.request
batas = time.monotonic() + 40
while time.monotonic() < batas:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/api/health", timeout=3) as r:
            if json.load(r).get("status") == "ok":
                sys.exit(0)
    except Exception:
        pass
    time.sleep(1)
sys.exit(1)
PY
}
port_aktif() {
	p=$(sed -n 's/^NS_DENGAR_PORT=//p' "$ETC/env" 2>/dev/null | head -n 1)
	case "$p" in ''|*[!0-9]*) echo "$PORT_BAWAAN" ;; *) echo "$p" ;; esac
}

if [ "$MODE" = hapus ]; then
	judul 2/2 "Menghapus program dan layanan (env dan data dipertahankan)"
	if [ "$TANPA_SYSTEMD" = 0 ]; then
		systemctl disable --now nusantara-shield.service >/dev/null 2>&1 || true
	fi
	rm -f "$UNIT" "$PEMBUNGKUS"
	[ "$TANPA_SYSTEMD" = 0 ] && systemctl daemon-reload
	rm -rf "$OPT"
	info "Terhapus: $OPT, $UNIT, $PEMBUNGKUS"
	info "Dipertahankan: $ETC (kunci audit, sandi) dan $VARLIB (log audit, Buku Rantai Bukti)."
	info "Untuk menghapus SEMUANYA (tidak bisa dibatalkan): rm -rf $ETC $VARLIB $VARLOG && userdel $PENGGUNA"
	exit 0
fi

if [ "$MODE" = kembali ]; then
	judul 2/2 "Kembali ke rilis sebelumnya"
	[ -L "$OPT/sebelumnya" ] || gagal 14 "tidak ada rilis sebelumnya yang tercatat di $OPT/sebelumnya"
	tujuan=$(readlink "$OPT/sebelumnya"); kini=$(readlink "$OPT/kini" 2>/dev/null || true)
	[ -d "$OPT/$tujuan" ] || gagal 14 "folder rilis sebelumnya ($OPT/$tujuan) sudah tidak ada"
	ln -sfn "$tujuan" "$OPT/kini.baru" && mv -Tf "$OPT/kini.baru" "$OPT/kini" || gagal 14 "tautan kini tidak bisa diganti"
	[ -n "$kini" ] && { ln -sfn "$kini" "$OPT/sebelumnya.baru" && mv -Tf "$OPT/sebelumnya.baru" "$OPT/sebelumnya"; }
	if [ "$TANPA_SYSTEMD" = 0 ]; then
		systemctl restart nusantara-shield.service || gagal 14 "layanan gagal dinyalakan ulang"
		uji_kesehatan "$(port_aktif)" || gagal 14 "rilis $tujuan tidak menjawab /api/health"
	fi
	printf '%s kembali %s -> %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${kini:-?}" "$tujuan" >>"$VARLOG/pemasangan.log" 2>/dev/null || true
	info "Aktif sekarang: $tujuan (sebelumnya: ${kini:-?})"
	exit 0
fi

# ------------------------------------------------------------------ 2. keaslian paket
judul 2/6 "Memeriksa keaslian paket (tanda tangan Ed25519 dan SHA256SUMS)"
for berkas in pasang.sh kunci-publik-rilis.pem manifest.json payload.tar.gz SHA256SUMS SHA256SUMS.sig; do
	[ -f "$PAKET/$berkas" ] || gagal 10 "$berkas tidak ada di paket. $belum_diubah"
done
sidik=$(openssl pkey -pubin -in "$PAKET/kunci-publik-rilis.pem" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)
if [ "$sidik" != "$SIDIK_JARI_KUNCI" ]; then
	gagal 10 "kunci publik di paket BUKAN kunci rilis Nusantara Shield.
  tertanam di skrip : $SIDIK_JARI_KUNCI
  di paket          : ${sidik:-tidak terbaca}
  $belum_diubah"
fi
info "Kunci rilis cocok: $sidik"
if ! openssl pkeyutl -verify -pubin -inkey "$PAKET/kunci-publik-rilis.pem" -rawin \
		-in "$PAKET/SHA256SUMS" -sigfile "$PAKET/SHA256SUMS.sig" >/dev/null 2>&1; then
	gagal 10 "tanda tangan SHA256SUMS TIDAK SAH: daftar sidik jari diubah atau ditandatangani kunci lain. $belum_diubah"
fi
info "Tanda tangan SHA256SUMS sah (Ed25519)."
if grep -qv '^[0-9a-f]\{64\}  [A-Za-z0-9._-]\{1,64\}$' "$PAKET/SHA256SUMS"; then
	gagal 10 "SHA256SUMS berisi baris yang tidak sah. $belum_diubah"
fi
for berkas in pasang.sh kunci-publik-rilis.pem manifest.json payload.tar.gz; do
	grep -q "  $berkas\$" "$PAKET/SHA256SUMS" || gagal 10 "$berkas tidak tercantum di SHA256SUMS. $belum_diubah"
done
( cd "$PAKET" && sha256sum -c --strict --quiet SHA256SUMS ) >&2 \
	|| gagal 10 "ada berkas paket yang tidak cocok dengan SHA256SUMS (rusak atau diubah). $belum_diubah"
info "Semua berkas paket cocok dengan SHA256SUMS (termasuk skrip ini)."

# ------------------------------------------------------------------ versi
kini_versi=""
[ -f "$OPT/kini/VERSI" ] && kini_versi=$(head -n 1 "$OPT/kini/VERSI")
if [ -n "$kini_versi" ]; then
	banding=$("$PY" -I -c 'import sys
a, b = (tuple(int(x) for x in v.split(".")) for v in sys.argv[1:3])
print("sama" if a == b else "turun" if a < b else "naik")' "$VERSI" "$kini_versi" 2>/dev/null) \
		|| gagal 14 "versi aktif ($kini_versi) tidak terbaca. $belum_diubah"
	if [ "$banding" = sama ]; then
		gagal 14 "versi $VERSI sudah aktif. Untuk memasang ulang: sudo sh pasang.sh --hapus (data dan env tetap), lalu ulangi. $belum_diubah"
	fi
	if [ "$banding" = turun ] && [ "$IZINKAN_TURUN" = 0 ]; then
		gagal 14 "paket ini ($VERSI) lebih lama dari versi aktif ($kini_versi). Tambahkan --izinkan-turun bila memang disengaja. $belum_diubah"
	fi
	info "Versi aktif $kini_versi → $VERSI"
fi

# ------------------------------------------------------------------ 3-4. isi payload dan ekstraksi
judul 3/6 "Memeriksa isi payload terhadap manifest (sebelum ekstraksi)"
mkdir -p "$OPT/rilis" || gagal 14 "$OPT tidak bisa dibuat"
chmod 755 "$OPT" "$OPT/rilis"
if ! mkdir "$OPT/.sedang-memasang" 2>/dev/null; then
	gagal 14 "pemasangan lain sedang berjalan (atau terhenti paksa). Bila yakin tidak ada, hapus $OPT/.sedang-memasang"
fi
SEMENTARA=$(mktemp -d "$OPT/.pasang.XXXXXX") || gagal 14 "folder sementara tidak bisa dibuat"
REL=$OPT/rilis/$VERSI
SELESAI=0
bersihkan() {
	[ -n "${SEMENTARA:-}" ] && rm -rf "$SEMENTARA"
	[ "$SELESAI" = 0 ] && [ -n "${REL_BARU:-}" ] && rm -rf "$REL_BARU"
	rmdir "$OPT/.sedang-memasang" 2>/dev/null
	return 0
}
trap bersihkan EXIT
trap 'exit 130' INT TERM

"$PY" -I - "$PAKET" "$SEMENTARA/isi" "$VERSI" "$SIDIK_JARI_KUNCI" <<'PY'
import hashlib, json, os, posixpath, stat, sys, tarfile
paket, tujuan, versi, sidik_kunci = sys.argv[1:5]

def gagal(kode, pesan):
    print(f"\nGAGAL (kode {kode}): {pesan}. Tidak ada yang dipasang.", file=sys.stderr)
    sys.exit(kode)

def sha256_berkas(jalur):
    h = hashlib.sha256()
    with open(jalur, "rb") as f:
        for blok in iter(lambda: f.read(1 << 20), b""):
            h.update(blok)
    return h.hexdigest()

try:
    with open(os.path.join(paket, "manifest.json"), encoding="utf-8") as f:
        m = json.load(f)
except (OSError, ValueError) as e:
    gagal(11, f"manifest.json tidak terbaca ({e})")
if m.get("skema") != "nusantara-shield/manifest/1" or m.get("versi") != versi or m.get("kunci_publik_sha256") != sidik_kunci:
    gagal(11, "manifest bukan untuk paket ini (skema, versi, atau kunci berbeda)")
isi = m.get("isi")
if not isinstance(isi, dict) or not isi:
    gagal(11, "manifest tidak berisi daftar berkas")
payload = os.path.join(paket, "payload.tar.gz")
if os.path.getsize(payload) != m["payload"]["ukuran"] or sha256_berkas(payload) != m["payload"]["sha256"]:
    gagal(12, "payload.tar.gz tidak sama dengan yang tercatat di manifest")
for nama in isi:
    if not isinstance(nama, str) or nama.startswith("/") or ".." in nama.split("/") or "\\" in nama \
            or posixpath.normpath(nama) != nama:
        gagal(11, f"manifest berisi jalur tidak sah: {nama!r}")

# Anggota tar diperiksa SATU PER SATU sebelum ada yang diekstrak.
terlihat = set()
with tarfile.open(payload, "r:gz") as tar:
    anggota = tar.getmembers()
    for a in anggota:
        n = a.name
        if n.startswith("/") or ".." in n.split("/") or "\\" in n or posixpath.normpath(n) != n:
            gagal(11, f"anggota payload berjalur tidak sah: {n!r}")
        if not (a.isreg() or a.isdir()):
            gagal(11, f"anggota payload bukan berkas biasa (tautan/perangkat): {n!r}")
        if a.isreg():
            if n not in isi:
                gagal(11, f"anggota payload tidak tercatat di manifest: {n!r}")
            if n in terlihat:
                gagal(11, f"anggota payload ganda: {n!r}")
            if a.size != isi[n]["ukuran"]:
                gagal(12, f"ukuran {n} tidak sama dengan manifest")
            terlihat.add(n)
    hilang = sorted(set(isi) - terlihat)
    if hilang:
        gagal(12, f"{len(hilang)} berkas manifest tidak ada di payload, mis. {hilang[0]}")
    print(f"  {len(terlihat)} anggota payload tercatat di manifest; tidak ada jalur, tautan, atau perangkat terlarang.")
    os.makedirs(tujuan, mode=0o755)
    tar.extractall(tujuan, members=anggota, filter="data")

# Setelah ekstraksi: SETIAP berkas dicocokkan lagi (isi, ukuran), dan tidak boleh ada yang lebih.
ditemukan = set()
for akar, folder, berkas in os.walk(tujuan):
    for nama in folder + berkas:
        jalur = os.path.join(akar, nama)
        if os.path.islink(jalur):
            gagal(12, f"tautan simbolik muncul setelah ekstraksi: {jalur}")
    for nama in berkas:
        jalur = os.path.join(akar, nama)
        relatif = os.path.relpath(jalur, tujuan).replace(os.sep, "/")
        if not stat.S_ISREG(os.lstat(jalur).st_mode) or relatif not in isi:
            gagal(12, f"berkas di luar manifest setelah ekstraksi: {relatif}")
        catatan = isi[relatif]
        if os.path.getsize(jalur) != catatan["ukuran"] or sha256_berkas(jalur) != catatan["sha256"]:
            gagal(12, f"isi {relatif} tidak cocok dengan SHA-256 di manifest")
        ditemukan.add(relatif)
if ditemukan != set(isi):
    gagal(12, f"berkas hilang setelah ekstraksi: {sorted(set(isi) - ditemukan)[:3]}")
with open(os.path.join(tujuan, "VERSI"), encoding="utf-8") as f:
    if f.read().strip() != versi:
        gagal(12, "berkas VERSI di payload tidak sama dengan versi paket")
print(f"  {len(ditemukan)} berkas diekstrak ke folder sementara; SHA-256 dan ukuran semuanya cocok dengan manifest.")
print(f"  Commit sumber: {m.get('commit', '?')}")
PY
rc=$?
case $rc in
	0) ;;
	10|11|12) exit "$rc" ;;
	*) gagal 12 "pemeriksaan payload berhenti tak terduga (kode $rc)" ;;
esac
judul 4/6 "Payload sah dan sudah diekstrak ke folder sementara"

# ------------------------------------------------------------------ 5. lingkungan Python
judul 5/6 "Menyiapkan lingkungan Python tanpa internet"
if [ -e "$REL" ]; then
	if [ "$(readlink "$OPT/kini" 2>/dev/null)" = "rilis/$VERSI" ]; then
		gagal 14 "rilis/$VERSI sedang aktif"
	fi
	rm -rf "$REL"                         # sisa pemasangan lama yang tidak aktif
fi
mv "$SEMENTARA/isi" "$REL" || gagal 14 "payload tidak bisa dipindahkan ke $REL"
REL_BARU=$REL
if [ "$TANPA_VENV" = 1 ]; then
	info "(mode uji --tanpa-venv: venv dan uji asap dilewati)"
else
	"$PY" -I -m venv --without-pip "$REL/.venv" || gagal 13 "venv tidak bisa dibuat dengan $PY"
	pip_whl=$(ls "$REL"/wheels/pip-*.whl 2>/dev/null | head -n 1)
	[ -n "$pip_whl" ] || gagal 13 "wheel pip tidak ada di payload"
	PIP_CONFIG_FILE=/dev/null "$REL/.venv/bin/python" -I "$pip_whl/pip" install --no-index --find-links "$REL/wheels" \
		--require-hashes --only-binary=:all: --disable-pip-version-check --no-input --no-cache-dir \
		--quiet -r "$REL/persyaratan-terkunci.txt" \
		|| gagal 13 "pustaka tidak bisa dipasang dari wheel di paket (tanpa internet)"
	info "Pustaka terpasang dari $(ls "$REL"/wheels/*.whl | wc -l) wheel lokal; setiap wheel dicocokkan SHA-256-nya oleh pip."
	ASAP=$(mktemp -d "$OPT/.asap.XXXXXX") || gagal 13 "folder uji asap tidak bisa dibuat"
	port=$("$PY" -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])') \
		|| gagal 13 "tidak bisa memilih port uji asap (antarmuka loopback mati?)"
	( cd "$ASAP" && exec env -i PATH=/usr/bin:/bin HOME="$ASAP" PYTHONDONTWRITEBYTECODE=1 \
		NS_MODE=prod NS_OPERATOR_PASSWORD=uji-asap-operator-0001 NS_VIEWER_PASSWORD=uji-asap-pengamat-001 \
		"$REL/.venv/bin/python" -m uvicorn app.main:app --app-dir "$REL" --host 127.0.0.1 --port "$port" \
		--log-level warning ) >"$ASAP/server.log" 2>&1 &
	pid=$!
	if uji_kesehatan "$port"; then
		kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
		rm -rf "$ASAP"
		info "Uji asap: aplikasi menyala dan /api/health menjawab \"ok\" (port sementara $port)."
	else
		kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
		tail -n 20 "$ASAP/server.log" >&2; rm -rf "$ASAP"
		gagal 13 "uji asap gagal: aplikasi tidak menjawab /api/health"
	fi
	if [ "$UJI" = 1 ]; then
		info "Menjalankan seluruh uji otomatis (bisa 1–2 menit)…"
		( cd "$REL" && env -i PATH=/usr/bin:/bin HOME="$SEMENTARA" PYTHONDONTWRITEBYTECODE=1 \
			"$REL/.venv/bin/python" -m pytest -q -p no:cacheprovider ) || gagal 13 "uji otomatis gagal"
	fi
fi

# ------------------------------------------------------------------ 6. pasang ke sistem
judul 6/6 "Memasang ke sistem"
if [ -z "$AWALAN" ]; then
	if ! getent passwd "$PENGGUNA" >/dev/null; then
		useradd --system --user-group --home-dir /var/lib/nusantara-shield --no-create-home \
			--shell /usr/sbin/nologin "$PENGGUNA" || gagal 14 "pengguna sistem $PENGGUNA tidak bisa dibuat"
		info "Pengguna sistem $PENGGUNA dibuat (tanpa login)."
	fi
	install -d -m 0750 -o root -g "$PENGGUNA" "$ETC"
	install -d -m 0700 -o "$PENGGUNA" -g "$PENGGUNA" "$VARLIB"
	install -d -m 0750 -o root -g "$PENGGUNA" "$VARLOG"
else
	mkdir -p "$ETC" "$VARLIB" "$VARLOG" "$(dirname "$UNIT")" "$(dirname "$PEMBUNGKUS")"
	chmod 0750 "$ETC" "$VARLOG"; chmod 0700 "$VARLIB"
fi

if [ -f "$ETC/env" ]; then
	info "$ETC/env sudah ada: dipertahankan apa adanya (kunci audit dan sandi tidak diganti)."
else
	acak() { openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | cut -c1-"$1"; }
	host="127.0.0.1,localhost${HOST_TAMBAHAN:+,$HOST_TAMBAHAN}"
	asal="http://127.0.0.1:$PORT_BAWAAN,http://localhost:$PORT_BAWAAN"
	baru=$(mktemp "$ETC/.env.XXXXXX") || gagal 14 "env tidak bisa dibuat"
	{
		echo "# Nusantara Shield — dibuat oleh pasang.sh $VERSI pada $(date -u +%Y-%m-%dT%H:%M:%SZ)."
		echo "# Berkas ini RAHASIA (izin 0640 root:$PENGGUNA). Jangan disalin ke repo atau media yang tidak diamankan."
		echo "# NS_AUDIT_KEY tidak boleh diganti: log audit lama hanya bisa diverifikasi dengan kunci yang sama."
		echo "NS_MODE=prod"
		echo "NS_AUDIT_KEY=$(openssl rand -hex 32)"
		echo "NS_OPERATOR_PASSWORD=$(acak 24)"
		echo "NS_VIEWER_PASSWORD=$(acak 24)"
		echo "NS_WAJIB_GANTI_SANDI=1"
		echo "# Pendaftaran Pengamat mandiri ditutup: akun baru dibuat Operator dari tab Akun (ubah ke 1 dengan sadar risikonya)."
		echo "NS_DAFTAR_PENGAMAT=0"
		echo "NS_ALLOWED_HOSTS=$host"
		echo "NS_ALLOWED_ORIGINS=$asal"
		echo "NS_ZONA_WAKTU=WIB"
		echo "NS_DENGAR_ALAMAT=127.0.0.1"
		echo "NS_DENGAR_PORT=$PORT_BAWAAN"
	} >"$baru" || gagal 14 "env tidak bisa ditulis"
	chmod 0640 "$baru"
	[ -z "$AWALAN" ] && chown root:"$PENGGUNA" "$baru"
	mv -f "$baru" "$ETC/env"
	info "$ETC/env dibuat: kunci audit acak 256-bit dan sandi awal acak (tidak dicetak ke layar)."
fi

install -m 0644 "$REL/installer/nusantara-shield.service" "$UNIT" || gagal 14 "berkas layanan tidak bisa dipasang"
install -m 0755 "$REL/installer/ns-verifikasi-audit" "$PEMBUNGKUS" || gagal 14 "ns-verifikasi-audit tidak bisa dipasang"

lama=$(readlink "$OPT/kini" 2>/dev/null || true)
ln -sfn "rilis/$VERSI" "$OPT/kini.baru" && mv -Tf "$OPT/kini.baru" "$OPT/kini" || gagal 14 "tautan kini tidak bisa diganti"
SELESAI=1
if [ -n "$lama" ] && [ "$lama" != "rilis/$VERSI" ]; then
	ln -sfn "$lama" "$OPT/sebelumnya.baru" && mv -Tf "$OPT/sebelumnya.baru" "$OPT/sebelumnya"
fi
info "Rilis aktif: $OPT/kini → rilis/$VERSI${lama:+ (sebelumnya: $lama)}"

if [ "$TANPA_SYSTEMD" = 0 ]; then
	systemctl daemon-reload
	systemctl enable nusantara-shield.service >/dev/null 2>&1 || gagal 14 "layanan tidak bisa diaktifkan"
	systemctl restart nusantara-shield.service
	if ! uji_kesehatan "$(port_aktif)"; then
		journalctl -u nusantara-shield.service -n 20 --no-pager >&2 2>/dev/null || true
		if [ -n "$lama" ] && [ "$lama" != "rilis/$VERSI" ]; then
			ln -sfn "$lama" "$OPT/kini.baru" && mv -Tf "$OPT/kini.baru" "$OPT/kini"
			systemctl restart nusantara-shield.service || true
			gagal 14 "versi $VERSI tidak menjawab /api/health; dikembalikan ke $lama"
		fi
		gagal 14 "layanan tidak menjawab /api/health; lihat: journalctl -u nusantara-shield"
	fi
	info "Layanan nusantara-shield aktif dan menjawab /api/health di 127.0.0.1:$(port_aktif)."
fi

# Rilis lama selain "kini" dan "sebelumnya" dibersihkan.
sebelumnya=$(readlink "$OPT/sebelumnya" 2>/dev/null || true)
for d in "$OPT"/rilis/*; do
	[ -d "$d" ] || continue
	r="rilis/$(basename "$d")"
	[ "$r" = "rilis/$VERSI" ] || [ "$r" = "$sebelumnya" ] || rm -rf "$d"
done

commit=$(sed -n 's/^ *"commit": "\([0-9a-f]*\)".*/\1/p' "$PAKET/manifest.json" | head -n 1)
printf '%s pasang %s commit=%s kunci=%s SHA256SUMS=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$VERSI" "$commit" \
	"$SIDIK_JARI_KUNCI" "$(sha256sum "$PAKET/SHA256SUMS" | cut -d' ' -f1)" >>"$VARLOG/pemasangan.log"

printf '\nSELESAI: Nusantara Shield %s terpasang.\n' "$VERSI"
if [ -z "$AWALAN" ]; then
	cat <<EOF
  Buka di komputer ini   : http://127.0.0.1:$(port_aktif)
  Sandi awal             : sudo grep _PASSWORD /etc/nusantara-shield/env   (wajib diganti saat login pertama)
  Status layanan         : systemctl status nusantara-shield
  Verifikasi log audit   : sudo ns-verifikasi-audit [--cocokkan <sidik jari dari LAPSIT>]
  Kembali ke versi lalu  : sudo sh pasang.sh --kembali
  Catatan pemasangan     : $VARLOG/pemasangan.log
EOF
	if [ "$TANPA_SYSTEMD" = 1 ]; then
		echo "  (--tanpa-systemd: layanan TIDAK dinyalakan. Nyalakan: systemctl daemon-reload && systemctl enable --now nusantara-shield)"
	fi
fi
exit 0
