# Contoh LAPSIT (Laporan Situasi) PDF

Dua berkas ini diekspor langsung dari aplikasi Nusantara Shield pada 13 November 2026 (kode v5.4.2; kop memuat nomor versi dari
`app/versi.py`), lewat tombol **Ekspor LAPSIT (PDF)** (`POST /api/lapsit`). Isinya tidak disunting. **Seluruh data sintetis**: nama
layanan bertanda "(contoh)", alamat IP dari blok dokumentasi RFC 5737, dan perintah ke perangkat jaringan masih simulasi.
Waktu di dalam PDF tertulis dalam WIB (atur dengan `NS_ZONA_WAKTU`).

| Berkas | Keadaan saat diekspor | Halaman |
| --- | --- | --- |
| [`contoh-lapsit-kondisi-normal.pdf`](contoh-lapsit-kondisi-normal.pdf) | Laporan rutin sesaat setelah *server* menyala dan Operator masuk: tidak ada insiden dan tidak ada peringatan | 1 |
| [`contoh-lapsit-insiden.pdf`](contoh-lapsit-insiden.pdf) | Setelah tiga latihan: *Akses OT tanpa izin*, *Ransomware* di RS Kesdam lalu isolasi (bukti BB-2026-001 lebih dulu), dan impor `docs/contoh-log/auth.log` | 3 |

Setiap halaman memuat **kop**: logo Nusantara Shield (digambar sebagai vektor dari `static/logo.svg`), identitas
posko, nomor laporan `LAPSIT/NS/<tanggal-jam>`, waktu cetak, dan jenisnya (*Laporan rutin* atau *Laporan insiden*),
serta **kaki halaman** "Halaman x dari y". Kop memakai identitas proyek sendiri dan sengaja tidak meniru kop surat,
lambang, atau stempel instansi mana pun.

Tujuh bagian yang selalu ada:

1. **Ringkasan eksekutif**: paragraf naratif tentang apa, kapan, bagaimana ditangani, dan dampaknya.
2. **Status layanan dan dampak operasional**: dampak terhadap misi tiap layanan dan prosedur kontinjensinya
   (perkiraan menurut profil layanan contoh).
3. **Insiden aktif dan tindakan**: kronologi gejala, langkah playbook dengan waktu eksekusi, T+detik, dan aktor,
   bukti SHA-256, MTTC, dan nomor laporan.
4. **Indikator kompromi (IoC)**: alamat ancaman, alamat sumber temuan, dan parameter Modbus beserta statusnya.
5. **Peringatan terbaru** dengan teknik MITRE ATT&CK dan label sumber data.
6. **Integritas log audit**: sidik jari HMAC-SHA256 dan cara auditor memverifikasinya.
7. **Pengesahan** dua tanda tangan; kotaknya sengaja kosong untuk diisi tangan.

## Membuat ulang

1. Jalankan *server* (lihat README utama), masuk sebagai Operator.
2. Untuk laporan rutin: buka tab **Audit & LAPSIT** → **Ekspor LAPSIT (PDF)**.
3. Untuk laporan insiden: di bilah **Latihan** klik **Akses OT tanpa izin**; pilih target *RS Kesdam · SIMRS (contoh)* →
   **Ransomware** → tahan **EKSEKUSI ISOLASI**; klik **Impor log…** dan pilih `docs/contoh-log/auth.log`; lalu ekspor LAPSIT.

Nomor, jam, dan sidik jari rantai audit akan berbeda di setiap percobaan karena mengikuti waktu dan isi sesi.
