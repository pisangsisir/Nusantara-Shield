# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026.
# Dilisensikan di bawah GNU General Public License v3.0; lihat berkas LICENSE.
"""
Uji paket pasang luring bertanda tangan untuk Ubuntu 24.04 (tools/kemas_installer.py, tools/kunci_rilis.py,
installer/pasang.sh).

Semua kunci di sini dibuat sementara oleh uji dan dibuang sesudahnya; kunci rilis sungguhan tidak pernah dipakai.
Uji yang MENJALANKAN pasang.sh memakai mode --awalan (dipasang di folder sementara, tanpa root/useradd/systemctl)
dan hanya berjalan di Linux x86_64 yang memiliki /usr/bin/python3.12 dan OpenSSL 3 (seperti Ubuntu 24.04).
Di komputer lain uji itu dilewati; uji pembuat paket dan kunci tetap berjalan.

Setiap jenis pemalsuan harus berhenti dengan kode keluarnya sendiri, dan tidak ada program yang terpasang:
  10 = keaslian (tanda tangan, kunci, SHA256SUMS) · 11 = anggota payload terlarang · 12 = isi tidak cocok manifest
  14 = versi · 20 = prasyarat · 2 = argumen.
"""
import gzip
import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

AKAR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(AKAR / "tools"))
import kemas_installer as ki  # noqa: E402
import kunci_rilis as kr  # noqa: E402
from kemas_rilis import ikut  # noqa: E402

WAKTU = 1_790_000_000
GIT = {"commit": "c0ffee" * 6 + "abcd", "waktu_commit": WAKTU, "pohon_kerja_bersih": True}
NAMA_JALUR_PRIVAT = "-----BEGIN" + " PRIVATE KEY"           # disusun, agar berkas uji ini sendiri tidak cocok
NAMA_JALUR_PRIVAT_ENK = "-----BEGIN ENCRYPTED" + " PRIVATE KEY"


def _openssl3() -> bool:
    try:
        return subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout.startswith("OpenSSL 3")
    except OSError:
        return False


BISA_PASANG = (sys.platform.startswith("linux") and platform.machine() == "x86_64"
               and Path("/usr/bin/python3.12").exists() and _openssl3() and shutil.which("sha256sum") is not None)
perlu_ubuntu = pytest.mark.skipif(not BISA_PASANG, reason="butuh Linux x86_64 + /usr/bin/python3.12 + OpenSSL 3")


# ------------------------------------------------------------------ alat bantu
def unduh_palsu(tujuan: Path, kebutuhan: Path) -> None:
    """Pengganti pip download: dua wheel kecil yang isinya tetap (uji tidak butuh internet)."""
    assert "uvicorn[standard]" not in kebutuhan.read_text(encoding="utf-8")      # disesuaikan untuk target Linux
    (tujuan / "pip-24.0-py3-none-any.whl").write_bytes(b"wheel pip palsu untuk uji\n")
    (tujuan / "contoh_pustaka-1.0-py3-none-any.whl").write_bytes(b"wheel contoh untuk uji\n")


def pem_publik(privat) -> bytes:
    return privat.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def tandatangani(folder: Path, privat) -> None:
    ki.tulis_sha256sums(folder)
    (folder / "SHA256SUMS.sig").write_bytes(privat.sign((folder / "SHA256SUMS").read_bytes()))


def susun(keluar: Path, privat, versi: str = "5.2.0") -> Path:
    pub = keluar / "kunci-publik.pem"
    keluar.mkdir(parents=True, exist_ok=True)
    pub.write_bytes(pem_publik(privat))
    folder = ki.susun(keluar, pub, versi, unduh=unduh_palsu, periksa_git=False, git=GIT)
    tandatangani(folder, privat)
    return folder


def isi_payload(folder: Path) -> list[tuple[tarfile.TarInfo, bytes | None]]:
    with tarfile.open(folder / "payload.tar.gz", "r:gz") as tar:
        return [(a, tar.extractfile(a).read() if a.isreg() else None) for a in tar.getmembers()]


def ganti_payload(folder: Path, privat, anggota, ubah_manifest=None) -> None:
    """Menulis payload baru, memperbarui sidik jari payload di manifest, lalu MENANDATANGANI ULANG dengan kunci rilis.
    Mensimulasikan kunci bocor atau pembuat paket yang keliru: lapisan pemeriksaan isi harus tetap menangkapnya."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz, tarfile.open(fileobj=gz, mode="w") as tar:
        for info, data in anggota:
            tar.addfile(info, io.BytesIO(data) if data is not None else None)
    (folder / "payload.tar.gz").write_bytes(buf.getvalue())
    m = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    m["payload"].update(sha256=ki.sha256(folder / "payload.tar.gz"), ukuran=len(buf.getvalue()))
    if ubah_manifest:
        ubah_manifest(m)
    (folder / "manifest.json").write_text(json.dumps(m), encoding="utf-8")
    tandatangani(folder, privat)


def pasang(folder: Path, root: Path, *argumen: str, os_release: str = 'ID=ubuntu\nVERSION_ID="24.04"\n'):
    rilis = root.parent / f"{root.name}-os-release"
    rilis.write_text(os_release, encoding="utf-8")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "NS_PASANG_OS_RELEASE": str(rilis), "LC_ALL": "C.UTF-8"}
    return subprocess.run(["sh", str(folder / "pasang.sh"), "--awalan", str(root), *argumen],
                          capture_output=True, text=True, env=env, timeout=120)


def terpasang(root: Path) -> list[str]:
    rilis = root / "opt" / "nusantara-shield" / "rilis"
    return sorted(p.name for p in rilis.iterdir()) if rilis.exists() else []


# ------------------------------------------------------------------ fixture
@pytest.fixture(scope="module")
def kunci():
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture(scope="module")
def paket_asli(tmp_path_factory, kunci) -> Path:
    return susun(tmp_path_factory.mktemp("rilis"), kunci)


@pytest.fixture
def paket(paket_asli, tmp_path) -> Path:
    salinan = tmp_path / "unduhan" / paket_asli.name
    shutil.copytree(paket_asli, salinan)
    return salinan


# ------------------------------------------------------------------ pembuat paket (semua sistem operasi)
def test_paket_tersusun_lengkap_terkunci_dan_tanpa_rahasia(paket_asli, kunci):
    sums = (paket_asli / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    assert sorted(b.split("  ")[1] for b in sums) == sorted(ki.BERKAS_PAKET)
    m = json.loads((paket_asli / "manifest.json").read_text(encoding="utf-8"))
    assert m["versi"] == "5.2.0" and m["commit"] == GIT["commit"] and m["python"] == "/usr/bin/python3.12"
    assert m["kunci_publik_sha256"] == kr.sidik_jari_kunci(pem_publik(kunci))
    assert m["isi"]["app/main.py"]["sha256"] == ki.sha256(AKAR / "app" / "main.py")
    assert ".env" not in m["isi"] and ".env.example" in m["isi"]           # contoh boleh, rahasia tidak
    for terlarang in ("data/", ".venv/", ".git/", "dist/"):
        assert not any(n.startswith(terlarang) for n in m["isi"]), terlarang
    assert {"installer/nusantara-shield.service", "installer/ns-verifikasi-audit", "tools/verifikasi_audit.py",
            "VERSI", "persyaratan-terkunci.txt"} <= set(m["isi"])
    skrip = (paket_asli / "pasang.sh").read_text(encoding="utf-8")
    assert "@@VERSI@@" not in skrip and "@@SIDIK_JARI_KUNCI@@" not in skrip and 'VERSI="5.2.0"' in skrip and m["kunci_publik_sha256"] in skrip
    for info, _ in isi_payload(paket_asli):
        assert info.isreg() and info.uid == 0 and info.mtime == WAKTU and info.mode in (0o644, 0o755)
    kunci_pip = next(d for i, d in isi_payload(paket_asli) if i.name == "persyaratan-terkunci.txt").decode().splitlines()
    assert kunci_pip == [f"contoh-pustaka==1.0 --hash=sha256:{m['isi']['wheels/contoh_pustaka-1.0-py3-none-any.whl']['sha256']}",
                         f"pip==24.0 --hash=sha256:{m['isi']['wheels/pip-24.0-py3-none-any.whl']['sha256']}"]


def test_payload_deterministik_dari_commit_dan_wheel_yang_sama(paket_asli, kunci, tmp_path):
    kedua = susun(tmp_path / "ulang", kunci)
    assert ki.sha256(kedua / "payload.tar.gz") == ki.sha256(paket_asli / "payload.tar.gz")
    assert (kedua / "manifest.json").read_bytes() == (paket_asli / "manifest.json").read_bytes()


def test_pembuat_paket_menolak_kunci_privat_wheel_ganda_dan_versi_aneh(tmp_path, kunci):
    privat_pem = tmp_path / "salah.pem"
    privat_pem.write_bytes(kunci.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
    with pytest.raises(ki.GagalKemas, match="PRIVAT"):
        ki.susun(tmp_path / "a", privat_pem, unduh=unduh_palsu, periksa_git=False, git=GIT)
    privat_pem.unlink()
    with pytest.raises(ki.GagalKemas, match="X.Y.Z"):
        ki.susun(tmp_path / "a", tmp_path / "x.pem", "5.2", unduh=unduh_palsu, periksa_git=False, git=GIT)
    roda = tmp_path / "roda"
    roda.mkdir()
    (roda / "numpy-2.0-cp312-cp312-manylinux_2_17_x86_64.whl").write_bytes(b"a")
    with pytest.raises(ki.GagalKemas, match="pip"):
        ki.kunci_persyaratan(roda)
    (roda / "numpy-2.1-cp312-cp312-manylinux_2_17_x86_64.whl").write_bytes(b"b")
    with pytest.raises(ki.GagalKemas, match="dua wheel"):
        ki.kunci_persyaratan(roda)


def test_perintah_unduh_hanya_wheel_linux_cpython_312():
    cmd = ki.perintah_unduh(Path("/tmp/w"), Path("/tmp/r.txt"))
    assert "--only-binary=:all:" in cmd and cmd[cmd.index("--python-version") + 1] == "3.12"
    platform_ = [cmd[i + 1] for i, c in enumerate(cmd) if c == "--platform"]
    assert "manylinux_2_39_x86_64" in platform_ and "manylinux2014_x86_64" in platform_
    assert all(p.endswith("x86_64") for p in platform_)


def test_bungkus_memeriksa_tanda_tangan_sebelum_membuat_tar(paket, kunci):
    tar_luar, catatan = ki.bungkus(paket)
    with tarfile.open(tar_luar) as tar:
        nama = sorted(a.name for a in tar.getmembers())
    assert nama == sorted([paket.name] + [f"{paket.name}/{b}" for b in
                                          (*ki.BERKAS_PAKET, "SHA256SUMS", "SHA256SUMS.sig")])
    teks = catatan.read_text(encoding="utf-8")
    assert ki.sha256(tar_luar) in teks and ki.sha256(paket / "SHA256SUMS") in teks
    assert "Signature Verified Successfully" in teks
    (paket / "SHA256SUMS.sig").write_bytes(ed25519.Ed25519PrivateKey.generate().sign(b"lain"))
    with pytest.raises(ki.GagalKemas, match="TIDAK SAH"):
        ki.bungkus(paket)


def test_kunci_rilis_terenkripsi_izin_600_dan_tanda_tangan_terverifikasi(tmp_path):
    sandi = tmp_path / "sandi.txt"
    sandi.write_text("sandi-rilis-uji-panjang-2026\n", encoding="utf-8")
    privat, publik = tmp_path / "rahasia" / "kunci-rilis.pem", tmp_path / "kunci-publik.pem"
    assert kr.main(["buat", "--kunci-privat", str(privat), "--kunci-publik", str(publik), "--sandi-berkas", str(sandi)]) == 0
    isi = privat.read_text(encoding="ascii")
    assert isi.startswith(NAMA_JALUR_PRIVAT_ENK) and (privat.stat().st_mode & 0o777) == 0o600
    assert kr.main(["buat", "--kunci-privat", str(privat), "--kunci-publik", str(publik),
                    "--sandi-berkas", str(sandi)]) == 2                        # tidak pernah menimpa
    assert privat.read_text(encoding="ascii") == isi
    berkas = tmp_path / "SHA256SUMS"
    berkas.write_text("a" * 64 + "  pasang.sh\n", encoding="utf-8")
    assert kr.main(["tandatangani", str(berkas), "--kunci-privat", str(privat), "--kunci-publik", str(publik),
                    "--sandi-berkas", str(sandi)]) == 0
    sig = tmp_path / "SHA256SUMS.sig"
    assert len(sig.read_bytes()) == 64
    serialization.load_pem_public_key(publik.read_bytes()).verify(sig.read_bytes(), berkas.read_bytes())
    if _openssl3():
        assert kr.verifikasi_openssl("openssl", publik, berkas, sig)          # perintah yang sama dengan pasang.sh
        r = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(publik), "-outform", "DER"], capture_output=True)
        assert hashlib.sha256(r.stdout).hexdigest() == kr.sidik_jari_kunci(publik.read_bytes())


def test_kunci_rilis_menolak_sandi_salah_sandi_pendek_kunci_di_repo_dan_kunci_bukan_pasangan(tmp_path):
    sandi, salah, pendek = (tmp_path / n for n in ("s", "x", "p"))
    sandi.write_text("sandi-rilis-uji-panjang-2026", encoding="utf-8")
    salah.write_text("bukan-sandi-yang-benar-sama-sekali", encoding="utf-8")
    pendek.write_text("pendek", encoding="utf-8")
    privat, publik = tmp_path / "k.pem", tmp_path / "pub.pem"
    assert kr.main(["buat", "--kunci-privat", str(privat), "--kunci-publik", str(publik), "--sandi-berkas", str(pendek)]) == 2
    assert not privat.exists()
    assert kr.main(["buat", "--kunci-privat", str(AKAR / "kunci" / "jangan.pem"), "--kunci-publik", str(publik),
                    "--sandi-berkas", str(sandi)]) == 2
    assert not (AKAR / "kunci" / "jangan.pem").exists()
    assert kr.main(["buat", "--kunci-privat", str(privat), "--kunci-publik", str(publik), "--sandi-berkas", str(sandi)]) == 0
    berkas = tmp_path / "SHA256SUMS"
    berkas.write_text("isi\n", encoding="utf-8")
    assert kr.main(["tandatangani", str(berkas), "--kunci-privat", str(privat), "--kunci-publik", str(publik),
                    "--sandi-berkas", str(salah)]) == 1
    assert not (tmp_path / "SHA256SUMS.sig").exists()
    lain = tmp_path / "lain.pem"
    lain.write_bytes(pem_publik(ed25519.Ed25519PrivateKey.generate()))
    assert kr.main(["tandatangani", str(berkas), "--kunci-privat", str(privat), "--kunci-publik", str(lain),
                    "--sandi-berkas", str(sandi)]) == 1
    assert not (tmp_path / "SHA256SUMS.sig").exists()


def test_tidak_ada_kunci_privat_di_berkas_rilis():
    for p in AKAR.rglob("*"):
        if p.is_file() and ikut(p) and p.stat().st_size < 5_000_000:
            teks = p.read_bytes()
            assert NAMA_JALUR_PRIVAT.encode() not in teks and NAMA_JALUR_PRIVAT_ENK.encode() not in teks, p
    for pem in (AKAR / "kunci").glob("*.pem"):
        assert b"PUBLIC KEY" in pem.read_bytes() and b"PRIVATE" not in pem.read_bytes()


# ------------------------------------------------------------------ pasang.sh (Linux x86_64 + python3.12 + OpenSSL 3)
@perlu_ubuntu
def test_pasang_berhasil_dan_hasilnya_sesuai_rancangan(paket, tmp_path):
    root = tmp_path / "root"
    r = pasang(paket, root, "--tanpa-venv")
    assert r.returncode == 0, r.stdout + r.stderr
    opt = root / "opt" / "nusantara-shield"
    assert os.readlink(opt / "kini") == "rilis/5.2.0" and (opt / "kini" / "VERSI").read_text().strip() == "5.2.0"
    assert (opt / "kini" / "app" / "main.py").read_bytes() == (AKAR / "app" / "main.py").read_bytes()
    env = (root / "etc" / "nusantara-shield" / "env").read_text(encoding="utf-8")
    nilai = dict(b.split("=", 1) for b in env.splitlines() if b and not b.startswith("#"))
    assert nilai["NS_WAJIB_GANTI_SANDI"] == "1"                              # sandi awal wajib diganti
    assert nilai["NS_DAFTAR_PENGAMAT"] == "0"                                # v5.4.1: tidak ada pendaftaran mandiri
    assert nilai["NS_MODE"] == "prod" and len(nilai["NS_AUDIT_KEY"]) == 64 and int(nilai["NS_AUDIT_KEY"], 16) >= 0
    assert len(nilai["NS_OPERATOR_PASSWORD"]) >= 12 and len(nilai["NS_VIEWER_PASSWORD"]) >= 12
    assert nilai["NS_OPERATOR_PASSWORD"] not in r.stdout + r.stderr                # sandi tidak dicetak
    assert ((root / "etc" / "nusantara-shield" / "env").stat().st_mode & 0o777) == 0o640
    assert ((root / "var" / "lib" / "nusantara-shield").stat().st_mode & 0o777) == 0o700
    assert (root / "etc" / "systemd" / "system" / "nusantara-shield.service").read_bytes() == \
        (AKAR / "installer" / "nusantara-shield.service").read_bytes()
    assert os.access(root / "usr" / "local" / "bin" / "ns-verifikasi-audit", os.X_OK)
    log = (root / "var" / "log" / "nusantara-shield" / "pemasangan.log").read_text(encoding="utf-8")
    assert "pasang 5.2.0" in log and GIT["commit"] in log and ki.sha256(paket / "SHA256SUMS") in log
    assert "Tanda tangan SHA256SUMS sah" in r.stdout and "SHA-256 dan ukuran semuanya cocok" in r.stdout
    assert not list(opt.glob(".pasang.*")) and not (opt / ".sedang-memasang").exists()   # folder sementara bersih


@perlu_ubuntu
def test_payload_diubah_satu_bita_ditolak_sebelum_ekstraksi(paket, tmp_path):
    data = bytearray((paket / "payload.tar.gz").read_bytes())
    data[len(data) // 2] ^= 0x01
    (paket / "payload.tar.gz").write_bytes(bytes(data))
    r = pasang(paket, tmp_path / "root")
    assert r.returncode == 10 and "tidak cocok dengan SHA256SUMS" in r.stderr
    assert terpasang(tmp_path / "root") == []


@perlu_ubuntu
def test_sha256sums_disunting_ditolak_oleh_tanda_tangan(paket, kunci, tmp_path):
    data = bytearray((paket / "payload.tar.gz").read_bytes())
    data[100] ^= 0xFF
    (paket / "payload.tar.gz").write_bytes(bytes(data))
    ki.tulis_sha256sums(paket)                         # penyerang memperbarui daftar, tetapi tidak punya kunci
    r = pasang(paket, tmp_path / "root")
    assert r.returncode == 10 and "TIDAK SAH" in r.stderr and terpasang(tmp_path / "root") == []


@perlu_ubuntu
def test_tanda_tangan_dari_kunci_lain_ditolak(paket, tmp_path):
    tandatangani(paket, ed25519.Ed25519PrivateKey.generate())
    r = pasang(paket, tmp_path / "root")
    assert r.returncode == 10 and "TIDAK SAH" in r.stderr


@perlu_ubuntu
def test_kunci_publik_ditukar_ditolak_oleh_sidik_jari_yang_tertanam(paket, tmp_path):
    penyerang = ed25519.Ed25519PrivateKey.generate()
    (paket / "kunci-publik-rilis.pem").write_bytes(pem_publik(penyerang))
    tandatangani(paket, penyerang)                    # tanda tangan sah untuk kunci penyerang
    r = pasang(paket, tmp_path / "root")
    assert r.returncode == 10 and "BUKAN kunci rilis" in r.stderr and terpasang(tmp_path / "root") == []


@perlu_ubuntu
def test_pasang_sh_disunting_atau_tanda_tangan_hilang_ditolak(paket, tmp_path):
    with (paket / "pasang.sh").open("a", encoding="utf-8") as f:
        f.write("# baris sisipan\n")
    r = pasang(paket, tmp_path / "root")
    assert r.returncode == 10 and "tidak cocok dengan SHA256SUMS" in r.stderr
    (paket / "SHA256SUMS.sig").unlink()
    r = pasang(paket, tmp_path / "root")
    assert r.returncode == 10 and "SHA256SUMS.sig tidak ada" in r.stderr


@perlu_ubuntu
def test_anggota_payload_naik_folder_ditolak_tanpa_menulis_apa_pun(paket, kunci, tmp_path):
    jahat = tarfile.TarInfo("app/../../../jahat.txt")
    jahat.size = 6
    ganti_payload(paket, kunci, isi_payload(paket) + [(jahat, b"jahat\n")])
    root = tmp_path / "root"
    r = pasang(paket, root)
    assert r.returncode == 11 and "berjalur tidak sah" in r.stderr
    assert not list(tmp_path.rglob("jahat.txt")) and terpasang(root) == []


@perlu_ubuntu
def test_anggota_payload_tautan_simbolik_ditolak(paket, kunci, tmp_path):
    tautan = tarfile.TarInfo("app/kunci-sistem")
    tautan.type, tautan.linkname = tarfile.SYMTYPE, "/etc/shadow"
    ganti_payload(paket, kunci, isi_payload(paket) + [(tautan, None)])
    r = pasang(paket, tmp_path / "root")
    assert r.returncode == 11 and "bukan berkas biasa" in r.stderr


@perlu_ubuntu
def test_anggota_payload_yang_tidak_tercatat_di_manifest_ditolak(paket, kunci, tmp_path):
    sisipan = tarfile.TarInfo("app/pintu_belakang.py")
    sisipan.size = 5
    ganti_payload(paket, kunci, isi_payload(paket) + [(sisipan, b"pass\n")])
    r = pasang(paket, tmp_path / "root")
    assert r.returncode == 11 and "tidak tercatat di manifest" in r.stderr


@perlu_ubuntu
def test_berkas_manifest_yang_hilang_dari_payload_ditolak(paket, kunci, tmp_path):
    ganti_payload(paket, kunci, [(i, d) for i, d in isi_payload(paket) if i.name != "app/audit.py"])
    r = pasang(paket, tmp_path / "root")
    assert r.returncode == 12 and "tidak ada di payload" in r.stderr and terpasang(tmp_path / "root") == []


@perlu_ubuntu
def test_isi_berkas_berbeda_dari_manifest_ditolak_setelah_ekstraksi_sementara(paket, kunci, tmp_path):
    anggota = []
    for info, data in isi_payload(paket):
        if info.name == "app/audit.py":
            data = data.replace(b"HMAC", b"hmac", 1)          # ukuran sama, isi beda
        anggota.append((info, data))
    ganti_payload(paket, kunci, anggota)
    root = tmp_path / "root"
    r = pasang(paket, root)
    assert r.returncode == 12 and "app/audit.py tidak cocok dengan SHA-256" in r.stderr
    assert terpasang(root) == [] and not list((root / "opt" / "nusantara-shield").glob(".pasang.*"))


@perlu_ubuntu
def test_versi_sama_dan_turun_ditolak_naik_dan_kembali_berjalan(paket, kunci, tmp_path):
    root = tmp_path / "root"
    assert pasang(paket, root, "--tanpa-venv").returncode == 0
    env_awal = (root / "etc" / "nusantara-shield" / "env").read_bytes()
    r = pasang(paket, root, "--tanpa-venv")
    assert r.returncode == 14 and "sudah aktif" in r.stderr
    lama = susun(tmp_path / "lama", kunci, "5.1.9")
    r = pasang(lama, root, "--tanpa-venv")
    assert r.returncode == 14 and "lebih lama" in r.stderr
    assert pasang(lama, root, "--tanpa-venv", "--izinkan-turun").returncode == 0
    opt = root / "opt" / "nusantara-shield"
    assert os.readlink(opt / "kini") == "rilis/5.1.9" and os.readlink(opt / "sebelumnya") == "rilis/5.2.0"
    assert (root / "etc" / "nusantara-shield" / "env").read_bytes() == env_awal     # kunci audit tidak diganti
    r = pasang(lama, root, "--kembali")
    assert r.returncode == 0 and os.readlink(opt / "kini") == "rilis/5.2.0"
    assert "kembali rilis/5.1.9 -> rilis/5.2.0" in (root / "var/log/nusantara-shield/pemasangan.log").read_text()


@perlu_ubuntu
def test_hapus_mempertahankan_env_dan_data_audit(paket, tmp_path):
    root = tmp_path / "root"
    assert pasang(paket, root, "--tanpa-venv").returncode == 0
    data = root / "var" / "lib" / "nusantara-shield" / "data"
    data.mkdir()
    (data / "audit_log.jsonl").write_text("{}\n", encoding="utf-8")
    r = pasang(paket, root, "--hapus")
    assert r.returncode == 0
    assert not (root / "opt" / "nusantara-shield").exists()
    assert not (root / "etc" / "systemd" / "system" / "nusantara-shield.service").exists()
    assert (root / "etc" / "nusantara-shield" / "env").exists() and (data / "audit_log.jsonl").exists()


@perlu_ubuntu
def test_prasyarat_tidak_terpenuhi_berhenti_tanpa_perubahan(paket, tmp_path):
    root = tmp_path / "root"
    r = pasang(paket, root, os_release='ID=ubuntu\nVERSION_ID="22.04"\n')
    assert r.returncode == 20 and "khusus Ubuntu 24.04" in r.stderr and "tidak ada yang diubah" in r.stderr
    assert list(root.iterdir()) == []
    r = pasang(paket, root, os_release='ID=debian\nVERSION_ID="12"\n')
    assert r.returncode == 20 and list(root.iterdir()) == []


@perlu_ubuntu
def test_argumen_salah_dan_templat_repo_ditolak(paket, tmp_path):
    def jalankan(skrip, *arg):
        return subprocess.run(["sh", str(skrip), *arg], capture_output=True, text=True, timeout=30)
    # Uji ini berjalan TANPA --awalan (bisa sebagai root). Pengaman: tanda tangan dibuang lebih dulu, sehingga
    # seandainya pemeriksaan argumen rusak pun skrip berhenti di langkah keaslian (kode 10) sebelum mengubah sistem.
    (paket / "SHA256SUMS.sig").unlink()
    r = jalankan(paket / "pasang.sh", "--tanpa-venv")                     # tanpa --awalan: tidak boleh
    assert r.returncode == 2 and "hanya untuk mode uji" in r.stderr
    assert jalankan(paket / "pasang.sh", "--pilihan-aneh").returncode == 2
    r = jalankan(AKAR / "installer" / "pasang.sh", "--awalan", str(tmp_path / "x"))
    assert r.returncode == 2 and "templat" in r.stderr
    assert jalankan(paket / "pasang.sh", "--bantuan").returncode == 0


def test_langkah_yang_terlewat_memberi_pesan_jelas_tanpa_menanyakan_sandi(tmp_path, monkeypatch, capsys):
    """Bila 'susun' gagal, 'tandatangani' tidak boleh menanyakan kata sandi lalu gagal (terkesan sandi salah),
    dan 'bungkus' tidak boleh berakhir dengan traceback."""
    monkeypatch.setattr(kr.getpass, "getpass", lambda *_: pytest.fail("kata sandi tidak boleh ditanyakan"))
    assert kr.main(["tandatangani", str(tmp_path / "tidak-ada" / "SHA256SUMS"),
                    "--kunci-publik", str(tmp_path / "pub.pem"), "--kunci-privat", str(tmp_path / "k.pem")]) == 2
    assert "kata sandi belum ditanyakan" in capsys.readouterr().err
    assert ki.main(["bungkus", str(tmp_path / "tidak-ada")]) == 1
    assert "jalankan dulu" in capsys.readouterr().err
