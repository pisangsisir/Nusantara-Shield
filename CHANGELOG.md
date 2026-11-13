# Riwayat Perubahan — Nusantara Shield

Seluruh kode dikembangkan sejak **15 Oktober 2026**, setelah publikasi program Kartika Cyber Hackathon 2026 (12 Oktober 2026), sesuai Deklarasi di Proposal §6.1 (Rulebook bagian G). Repositori Git ini dimulai pada **20 Oktober 2026**; riwayat sebelumnya disusun dari folder versi dan folder cadangan per fase yang tersimpan di laptop pengembang (beserta catatan `BACA-SAYA.txt`), bukan dari commit.

## Dokumen — 13 November 2026 (tanpa perubahan kode; versi tetap v5.4.2)

- **Dek: slide Lampiran C · Prinsip yang Bisa Diuji** (dek kini 10 slide). Enam prinsip, masing-masing dengan uji yang gagal bila prinsip itu dilanggar: bukti dulu, manusia memutus, luring penuh, tanpa tuduhan (hanya alamat RFC 5737), laporan dari jejak, dan riwayat terkunci. Catatan pembicaranya memuat lima jawaban tanya jawab baru (LLM awan, AI salah tebak, asal IP penyerang, peta lintas Kodam dan patroli media sosial, asal angka).
- **Contoh LAPSIT dibuat ulang** dari v5.4.2 (sebelumnya v5.3.0); isinya tidak disunting.
- Unduhan situs (dek PDF dan PPTX, contoh LAPSIT) dan sidik jarinya diperbarui. Proposal dan Dokumentasi Teknis tidak berubah.

## v5.4.2 — 12 November 2026

Dua batas yang paling mungkin ditanyakan Dewan Juri ditutup. Rilis v5.4.1 tidak diubah.

### Buka Insiden dari temuan log asli
- **Tombol Buka Insiden** di baris temuan tabel Peringatan, dan loket `POST /api/insiden/dari-temuan` (hanya Operator). _Server_ mengusulkan layanan (pemilik aset) dan playbook dari aturan: aturan IT → playbook baru **Intrusi dari log asli**, aturan OT → **Sabotase OT**. Operator yang memutuskan; impor saja tetap hanya menaikkan WASPADA.
- **Tanpa data rekaan:** aset terdampak, kronologi (waktu kejadian), label ATT&CK, judul, teks dampak LAPSIT, dan barang bukti mengikuti temuan, bukan templat latihan. Lapisan AI tidak memberi pola lalu lintas latihan ke aset itu; peta global tidak menggambar asal serangan.
- **SHA-256 asli berkas log** dicatat di berita acara bukti (sama dengan `sha256sum` berkas aslinya; isi impor kini tidak dipangkas). LAPSIT menyebut asal insiden dan sidik jarinya.
- Hanya temuan impor yang aktif, belum ditutup lewat triase, bukan Drill, dan belum pernah dibuka; satu insiden per layanan.

### Tahan tombol dijaga _server_
- `POST /api/tahan`: token sekali pakai saat tombol pemutus mulai ditahan, terikat akun, layanan, tombol, dan insiden; berlaku 15 detik.
- **Semua jalur pemutus** ditolak 428 tanpa token sah atau sebelum 0,5 detik (isolasi darurat 1,4 detik): Eksekusi Isolasi, tindakan pemutus satuan, centang manual langkah pemutus, dan Isolasi Darurat. Lencana langkah pemutus di Action Center kini terkunci; pemutusan hanya lewat tombol yang ditahan. Lama tahan dicatat di log audit.
- Ditulis jujur: menegakkan doktrin dari klien mana pun, bukan pengaman terhadap skrip yang sengaja menunggu.

### Pemeriksaan
- Pemeriksa terpisah yang tidak ikut membangun menemukan sembilan celah (terberat: centang manual langkah pemutus tanpa token, dan temuan Drill yang bisa dibuka sebagai log asli); semuanya ditambal dan dikunci uji.
- Diuji di peramban: impor auth.log → **Buka Insiden** → klik cepat tidak mengeksekusi → tahan penuh mengeksekusi dengan token → aset **TERISOLASI** dengan bukti tercatat.
- **26 uji baru** (`tests/test_insiden_temuan.py` 14, `tests/test_tahan.py` 11, rantai bukti +1). Total **485** (23 kelompok, ≈60 detik): Tangkal 135, Manusia 148, Bukti 37, Jejak 62, Luring 32, Pendukung 71.

## v5.4.1 — 11 November 2026

Tambalan dari tinjauan independen (sudut pandang Dewan Juri), ditambah satu fitur yang langsung menutup celah terbesarnya: Saksi Berjenjang Luring. Gagasan lain masuk peta jalan (Proposal §5.6).

### Saksi Berjenjang Luring — 11 November 2026 (branch `feature/saksi-berjenjang`)
- **Masalah:** penyerang yang menguasai _server_ posko bisa mengembalikan log dan berkas titik periksa ke keadaan lama; hasilnya tetap sah secara kriptografi. Yang menangkapnya hanya salinan di luar posko.
- **Ekspor Saksi** (tab Audit & LAPSIT, hanya Operator; `POST /api/saksi`): titik periksa baru beralasan `SAKSI`, lalu seluruh rantai titik periksa diunduh sebagai satu berkas JSON untuk diserahkan lewat media fisik. Tercatat `EKSPOR_SAKSI` di log audit; mode demo menolak dengan 409.
- **`tools/saksi.py`** untuk satuan atasan (pustaka bawaan Python, tanpa jaringan): `kunci`, `terima`, `status`, `rekap`, `periksa-tanda-terima`. Kiriman baru harus memuat seluruh isi kiriman lama, sama persis; lebih pendek → digulung mundur, isi lama berbeda → bercabang, keduanya ditolak. Setiap penerimaan masuk Buku Saksi (bernomor, berantai, bertanda tangan Ed25519 jenjang itu) dan menghasilkan Tanda Terima. Rekap diterima jenjang di atas dengan aturan yang sama, sehingga jenjang bawah yang menulis ulang bukunya sendiri ikut tertangkap.
- **`verifikasi_titik_periksa.py --saksi BERKAS`**: auditor di posko memakai saksi dari arsip atasan; rantai posko harus memuat seluruh titik periksa saksi.
- Penandatangan Ed25519 Python murni (RFC 8032) diuji identik dengan pustaka _cryptography_.
- **16 uji baru** (`tests/test_saksi.py`, aturan Jejak). Total **441** (21 kelompok, ≈55 detik): Tangkal 135, Manusia 123, Bukti 36, Jejak 44, Luring 32, Pendukung 71.
- Diuji ujung ke ujung di peramban: dua kali Ekspor Saksi dari _server_ yang menyimpan log ke berkas, diterima satuan atasan, saksi lama ditolak, rekap diterima jenjang atas, Tanda Terima sah, auditor `[COCOK]`; tombol nonaktif untuk Pengamat.
- Dokumen: Dokumentasi Teknis §2.7.2, README, Proposal §5.4 dan §5.6, catatan pembicara dek, situs, BACA-SAYA pemasang.

### Tinjauan independen Saksi Berjenjang — 11 November 2026 (branch `fix/saksi-tinjauan`)
Pemeriksa terpisah yang tidak ikut membangun fitur ini menguji dua putaran; sepuluh celah ditemukan dan direproduksi, semuanya ditambal:
- **Patokan dari Buku Saksi, bukan arsip** (temuan terberat): sebelumnya arsip kiriman yang hilang atau ditukar membuat kiriman mundur diterima. Kini pembanding diambil dari entri buku terakhir pengirim itu; arsip dipakai hanya bila sidik jarinya sama dengan yang tercatat. Arsip yang lebih baru tetapi belum tercatat (komputer mati di tengah pencatatan) tetap jadi patokan. Nama berkas arsip memuat sidik jarinya sehingga tidak saling menimpa; penulisan berbasis bita dengan `fsync` direktori.
- Label pengirim dibersihkan dari karakter kendali terminal (ESC, CR, LF, arah teks, *surrogate*); nama yang mirip (huruf besar/kecil, tanda baca, lebar huruf) dengan sidik jari lain ditolak kecuali `--harap`.
- Jumlah entri yang mundur atau buku yang hilang dari kepala titik periksa ditolak; kunci Ed25519 berorde kecil ditolak pemeriksa.
- Buku Saksi terpotong, JSON bersarang sangat dalam, direktori, arsip rusak, berkas > 64 MB → kode keluar 1/2 dengan pesan, bukan *traceback*.
- LAPSIT mencetak nomor dan waktu Berkas Saksi terakhir (WIB/WITA/WIT) dan perintah `--saksi`; bila belum pernah ada, LAPSIT mengingatkan untuk mengekspor.
- Sampul dek: 11 November 2026.
- **18 uji baru** (`tests/test_saksi.py` kini 34). Total **459** (≈55 detik): Tangkal 135, Manusia 123, Bukti 36, Jejak 62, Luring 32, Pendukung 71.

### Keamanan dan ketahanan (branch `fix/audit-v541`)
- **Impor log tahan berkas beracun.** Pola kolom firewall diganti pencarian kolom yang tidak bisa mundur berulang; satu baris 18 KB berisi `SRC=1 DST=1` berulang sebelumnya menahan _server_ 108 detik, kini selesai seketika. Baris lebih dari 4.096 karakter dilewati; JSON bersarang terlalu dalam, sel CSV raksasa, dan tahun di luar jangkauan ditolak 422 atau dilewati, tidak menjadi galat 500.
- **Penguraian di luar kunci keadaan.** Berkas impor diurai sebelum kunci keadaan diambil, jadi dasbor Operator lain tidak membeku selama impor.
- **Body impor baru dibaca bila token sah.** Sebelumnya cukup ada token apa pun untuk mengirim ≈2,6 MB; kini token palsu ditolak 401 sebelum body dibaca.
- **Pendaftaran Pengamat tertutup di produksi.** `pasang.sh` menulis `NS_DAFTAR_PENGAMAT=0` ke env baru.
- **Penggulungan mundur tertangkap.** `tools/verifikasi_titik_periksa.py --minimal-titik N` menolak riwayat yang berhenti sebelum nomor titik periksa yang tercatat di LAPSIT terakhir; petunjuk verifikasi di LAPSIT kini mencetak opsi ini.
- Log audit di-`fsync` setelah setiap entri.
- Uji 425 setelah tambalan ini (sebelumnya 411); 441 setelah Saksi Berjenjang Luring.

### Dokumen
- Klaim yang terlalu tinggi dikoreksi: kebutuhan penyimpanan (terukur ≈400 MB setelah terpasang, bukan 50 MB), Pengamat juga mencetak LAPSIT, pengecualian batas 16 KB untuk impor log, angka 1,2 detik sebagai jeda alur purwarupa, tahan 0,6 detik dijaga di peramban.
- Batas baru ditulis terbuka di Dokumentasi Teknis §2.7: temuan log asli belum bisa langsung dibuka menjadi insiden, akun belum bisa dinonaktifkan, tingkat alarm keliru belum diukur.
- Catatan pembicara dek memuat jawaban lima pertanyaan tersulit.

### Tautan repositori dan situs mengikuti nama baru — 9 November 2026 (branch `fix/tautan-nama-repo`)
- Repositori berganti nama menjadi `Nusantara-Shield`. Tautan di dek, poster, README, dan situs diganti; poster dan unduhan situs dibangun ulang.
- Alamat situs kini **https://pisangsisir.github.io/Nusantara-Shield/**. Alamat situs lama tidak dialihkan GitHub Pages; tautan `github.com` nama lama tetap dialihkan.

## v5.4.0 — 9 November 2026

Rilis ini menggabungkan semua perubahan sejak v5.2.0. Versi 5.3.0 tidak diterbitkan sebagai rilis tersendiri; isinya (titik periksa Ed25519 dan tinjauan CTO) ikut di sini.

### Penyegaran materi v5.4.0 — 9 November 2026 (branch `feature/rilis-540`)
- `app/versi.py` → **5.4.0**; nomor versi di dek, poster, README, Proposal, dan Dokumentasi Teknis ikut diperbarui. Penyebutan "(v5.3.0)" yang merujuk sejarah dibiarkan.
- Jumlah uji **411** (20 kelompok, ≈55 detik di Linux) di semua bahan; ringkasan doktrin Tangkal 122, Manusia 123, Bukti 36, Jejak 27, Luring 32, Pendukung 71. Tabel uji Dokumentasi Teknis kini punya baris Drill Kesiapan (36) dan blok terminalnya dibangkitkan ulang.
- Dek: Drill Kesiapan dan impor Wazuh/Suricata masuk slide Mode Berdaulat dan Lampiran B (Fungsionalitas); dua jawaban tanya jawab baru di catatan pembicara.
- Poster: fungsi Detect kini memuat **impor berkas Wazuh dan Suricata** (BERJALAN) menggantikan butir peta jalan "sensor jaringan nyata"; fungsi Protect memuat **Drill Kesiapan berskor** (BERJALAN). Sambungan langsung ke sensor tetap belum dibangun.
- Unduhan situs dibangun ulang dari sumber terbaru (`tools/bangun_situs.py`).
- Situs: huruf judul dan isi diganti **Inter** (SIL OFL, disimpan sendiri di `situs/huruf/`). Judul tidak lagi dipadatkan; jarak huruf dan baris dilonggarkan agar nyaman dibaca. Huruf mono HUD tetap JetBrains Mono. Bricolage dan Plus Jakarta Sans masih dipakai untuk PDF unduhan.

### Situs bergaya layar posko — 9 November 2026 (branch `feature/situs-hud`)
- Situs dirombak memakai gaya asli dasbor: latar biru malam, hijau neon untuk AMAN/siap, kuning WASPADA, merah KRITIS, label HUD huruf mono, dan ikon garis yang sama dengan aplikasi.
- Pembuka: radar beranimasi (zona DMZ, internal, kendali OT) dan panel status sistem; pita kata kunci doktrin.
- Bagian bernomor 01–10 dengan *punchline* masing-masing: masalah (angka besar bersumber), lima aturan doktrin beserta jumlah ujinya, pipeline OODA dan urutan saat isolasi, **layar asli** dalam bingkai jendela bertab, Drill Kesiapan (bento dengan contoh kartu nilai), alur sensor Wazuh/Suricata, perbandingan ✓/✗, penerapan dan batas peran, unduhan bersidik jari, serta tanya jawab berakordeon.
- Tetap tanpa CDN dan tanpa font daring; gerak dimatikan bila perangkat meminta gerak dikurangi.

### Situs untuk Dewan Juri — 9 November 2026 (branch `feature/situs`)
- **`situs/`**: satu halaman statis yang memuat semua bahan penilaian. Isinya: urutan doktrin sebagai jalur keputusan bercap waktu, masalah (pelajaran PDNS ≈49 jam dan empat kelemahan respons manual), siklus OODA dengan tangkapan layar, Drill Kesiapan, impor Wazuh/Suricata, perbandingan menurut jenis alat, batas yang kami akui, langkah penerapan dan batas peran, serta unduhan dengan sidik jari SHA-256 dan tiga perintah untuk juri.
- **Huruf disimpan sendiri** (Bricolage Grotesque, Plus Jakarta Sans, JetBrains Mono; SIL OFL): tampil sama di semua sistem operasi, tanpa CDN dan tanpa font daring. Mode gelap mengikuti pengaturan perangkat. Video YouTube baru dimuat setelah tombol ditekan (`situs/situs.js`, isi `VIDEO_ID` setelah video diunggah).
- **`tools/bangun_situs.py`**: Proposal dan Dokumentasi Teknis dicetak ulang dari Markdown ke PDF A4; dek 9 slide ke PDF dan PPTX; Panduan Belajar, poster, contoh LAPSIT, dan contoh log disalin; sidik jari ditulis ke `situs/unduh/SHA256SUMS` dan ke tabel unduhan.
- **`.github/workflows/situs.yml`**: menerbitkan `situs/` ke GitHub Pages setiap kali master berubah (aktifkan sekali: Settings → Pages → Source: GitHub Actions).

### Drill Kesiapan: skenario OT dari Suricata — 9 November 2026 (branch `feature/drill-ot`)
- Skenario kedua **"Perintah asing ke pengendali genset"**: log cerita dalam format **Suricata `eve.json`**, dinilai lewat jalur impor yang sama (butuh PR impor Wazuh/Suricata). HMI resmi membaca register (bukan temuan); stasiun kerja kantor menyeberang ke zona kendali lalu menulis register jadwal start genset → tiga aturan OT harus muncul.
- Insiden latihan *Sabotase OT* di Genset RS Kesdam; pertanyaan per fase menekankan **genset tidak dimatikan** dan jalur kantor → zona kendali yang diputus (NIST SP 800-82).
- Cerita OT ditaruh pada pukul 14.00 terakhir yang sudah lewat (zona waktu satuan) agar selalu di luar jendela pemeliharaan 22.00–02.00, kapan pun drill dibuka.
- Katalog drill kini membawa format log, cerita, dan pertanyaan per skenario; tampilan menyesuaikan format.
- **8 uji baru**; total **411 uji**. *Deface* situs satuan masuk peta jalan (butuh jenis insiden dan aturan baru).

### Impor keluaran Wazuh dan Suricata — 9 November 2026 (branch `feature/impor-wazuh-suricata`)
- **Alasan:** satuan yang sudah memasang Wazuh (IT) dan Suricata (OT) tidak perlu mengubah apa pun untuk mencoba Nusantara Shield. Keluaran sensornya cukup diimpor.
- `app/impor_log.py` kini membaca **Wazuh `alerts.json`** dan **Suricata `eve.json`** (JSON per baris, atau satu larik JSON hasil ekspor) lewat jalur impor yang sama:
  - Wazuh: grup `authentication_failed` / `invalid_login` / `authentication_success` → upaya *login* (alamat dari `data.srcip`, aset dari `agent.ip`). Peringatan agregat Wazuh (5763 *brute force*), `sudo`, dan FIM **tidak** dihitung: rentetan dinilai aturan kita sendiri dengan ambang terbuka.
  - Suricata: `flow`/`alert`/`netflow` → koneksi (ke *port* 502 aset OT → koneksi ke zona kendali); `modbus` → perintah Modbus dari `request.function_raw`. Jam perintah diambil dari stempel waktu sensor, bukan zona waktu *server*.
  - Hanya membaca berkas: tidak memasang, mengatur, atau menghubungi sensor; tidak ada *active response* atau IPS. Temuan tetap hanya menaikkan WASPADA.
- Contoh sintetis baru: `docs/contoh-log/wazuh-alerts.json` (14 baris) dan `suricata-eve.json` (26 baris).
- **7 uji baru** (ditulis lebih dulu; 5 mutasi tertangkap, termasuk agregat Wazuh ikut dihitung dan jam Modbus memakai zona waktu *server*). Total **403 uji**.
- **Batas peran** ditulis di README dan Proposal §5.3: hanya aset TNI; insiden sipil ranah BSSN, Komdigi, dan Polri; PDNS dipakai sebagai pelajaran.
- Angka uji di dek, poster, dan blok terminal Dokumentasi Teknis diperbarui di tahap penyegaran materi sebelum rilis.

### Drill Kesiapan — 9 November 2026 (branch `feature/drill-kesiapan`)
- **Masalah:** narasumber diskusi komunitas (merujuk Satsiber TNI dan TTIS TNI AD) dan webinar pembekalan lomba menyebut masalah yang sama: SDM siber spesialis langka, dan tim yang jarang berlatih tidak siap saat insiden. Perpres 82/2022 Pasal 4 dan 15 mewajibkan simulasi tanggap Insiden Siber bagi sektor kesehatan dan pertahanan.
- **Baru: `app/drill.py` dan tab Drill Kesiapan** (Alat Operator; pintasan di panel Latihan).
  - Log cerita sintetis (18 baris auth.log, alamat RFC 5737) masuk lewat **jalur impor log yang sama** dengan log asli; tidak ada temuan yang disuntikkan. Kunci jawaban deteksi melaporkan aturan yang seharusnya menangkap, termasuk bila ada yang diam (*detection drill*).
  - Insiden latihan *Cadangan mati* dimulai di RS Kesdam · SIMRS; Operator menanganinya dari Action Center seperti biasa.
  - Empat pertanyaan per fase NIST SP 800-61 (Deteksi, Analisis, Penahanan, Pemulihan). Kunci jawaban tidak dikirim ke browser sebelum dijawab; sekali jawab.
  - **Nilai 0–100 dari jejak tercatat**, rumus terbuka: ketepatan 40 · bukti sebelum putus 30 (susulan 15, darurat tanpa bukti 0) · kecepatan penahanan 30 (MTTC ≤180/420/900 detik = 30/20/10). Ambang kecepatan adalah target latihan purwarupa, bukan standar resmi.
  - Log audit: `DRILL_MULAI`, `DRILL_JAWAB` (benar/salah, bukan isi pilihan), `DRILL_SELESAI`, `DRILL_DIBATALKAN`. LAPSIT memuat bagian Drill Kesiapan bertanda **LATIHAN** bila ada hasil; LAPSIT rutin tanpa drill tidak berubah.
- `Menara.respons()` (app/telemetri.py): jejak respons per layanan (bukti, isolasi darurat, MTTC, verifikasi, pulih) yang tetap ada setelah insiden ditutup.
- **28 uji baru** (`tests/test_drill.py`), ditulis lebih dulu, dan 1 uji kamus istilah. Diuji balik dengan 9 mutasi (kunci bocor, jawab ulang, darurat bernilai penuh, deteksi palsu, ambang diubah, loket terbuka untuk Pengamat, drill tidak dibatalkan saat reset, jejak bukti tidak dicatat, antrean SOAR tidak diproses); semuanya tertangkap. Total **396 uji** dalam 20 kelompok.
- Dokumen: Dokumentasi Teknis §3.5 dan kamus istilah; Proposal §2.4 (kelemahan keempat), §3.3, §5.4, §6.4; README.
- **Batas:** satu skenario; *tabletop exercise* untuk pimpinan belum dibangun; riwayat nilai di memori *server* (jejak permanennya di log audit).

### Tinjauan ahli TI (CTO) — 9 November 2026 (branch `fix/review-cto`, masuk v5.3.0)
- **Satu definisi ≈1,2 detik** di semua slide dan dokumen: dari Operator selesai menahan tombol sampai jalur pertama terputus; bukti diamankan di awal jeda. Ditulis terus terang bahwa di purwarupa pengambilan bukti tersimulasi.
- **Jawaban soal *memory dump*** (Dokumentasi Teknis §3.2, catatan Slide 6): salinan memori 8 GB bisa makan beberapa menit. Rancangan tiga lapis: bukti ringkas sebelum diputus, salinan memori penuh sesudah diputus, Isolasi Darurat bila macet. Lapis 1–2 belum dibangun; lapis 3 sudah berjalan.
- **66% → 20% diberi satuan:** skor peluang serangan pengendali genset (heuristik 0–100%: 0,80 × 0,75 × 1,1; Perketat ×0,3), bukan probabilitas terkalibrasi.
- **Satu angka CPU utama ≈1,5%** (300 layar, versi akhir); −74% menjadi riwayat optimasi.
- **Uji diringkas per aturan doktrin** di keluaran `./run_tests.sh` (`tests/conftest.py`); slide 4 menampilkan ringkasan itu dengan huruf lebih besar, dan kartu "367 uji" diganti "5 aturan doktrin".
- **"±" diganti "≈"** di dek, poster, README, Proposal, Dokumentasi Teknis, dan teks kode (± berarti toleransi).
- **"409" diterjemahkan "ditolak sistem"** di dek dan poster; kode HTTP tetap disebut dalam kurung untuk pembaca teknis.
- **Kamus singkatan** dek, Proposal, dan Dokumentasi Teknis: ditambah ASGI, ATT&CK, Kesdam, Mabes, RSPAD (dek juga Dansat, Kodam, Pussiberad).
- **Kronologi PDNS dibetulkan** sesuai keterangan BSSN (17 Juni 23.15 WIB upaya mematikan Windows Defender; 20 Juni 00.54 aktivitas jahat; ≈49 jam). Kalimat "cadangan dimatikan tiga menit sebelum enkripsi" dihapus karena tidak ada sumbernya.
- **NIST CSF 2.0:** lencana dek kini "Dipetakan ke NIST CSF 2.0 · Dok. Teknis §2.6" (pemetaan per kategori dengan uji pembuktinya), bukan "selaras".
- **Sampul** ditambahkan di dek (nama tim, ketua/penyaji, kategori, versi); dek kini 9 slide.

### v5.3.0 · Titik periksa Ed25519 dengan kunci berevolusi — 1 November 2026 (branch `feature/titik-periksa-ed25519`)
- **Masalah:** HMAC memakai satu kunci untuk membuat sekaligus memeriksa. Penyerang yang membobol *server* dan memegang `NS_AUDIT_KEY` bisa menulis ulang riwayat dengan sidik jari yang sah (Dokumentasi Teknis §2.7, peta jalan §2.9).
- **Baru: `app/titik_periksa.py`.**
  - Saat pertama menyala dengan `NS_AUDIT_KEY`, *server* membuat kunci Ed25519 periode 1 dan mencatat sidik jari akarnya (`KUNCI_TITIK_PERIKSA_DIBUAT`).
  - Setiap `NS_TITIK_PERIKSA_SETIAP` entri (bawaan 25) dan setiap ekspor LAPSIT, kepala log audit dan Buku Rantai Bukti (jumlah entri + SHA-256 kumulatif) ditandatangani kunci periode berjalan. Titik periksa itu mengesahkan kunci periode berikutnya, lalu kunci lama ditimpa (berkas status izin 600).
  - Bila berkas titik periksa dan berkas status tidak cocok, titik periksa dinonaktifkan dan akar baru tidak dibuat diam-diam.
- **Baru: `tools/verifikasi_titik_periksa.py`.** Auditor memeriksa dengan sidik jari akar saja, tanpa `NS_AUDIT_KEY`. Hanya pustaka bawaan Python (Ed25519 rujukan RFC 8032).
- LAPSIT bagian 6 mencetak nomor titik periksa dan sidik jari akar; `GET /api/audit/verifikasi` ikut mengembalikan ringkasannya.
- **15 uji baru** (`tests/test_titik_periksa.py`), ditulis lebih dulu. Termasuk penyerang yang memegang `NS_AUDIT_KEY` dan kunci periode berjalan sekaligus. Diuji balik dengan mutasi: tanpa cek tanda tangan, tanpa cek akar, tanpa cek pengesahan kunci, atau kunci lama tidak dihapus → uji gagal. Total **367 uji** dalam 19 kelompok.
- **Perbaikan sebelum terbit (PR #32):** uji pemasangan produksi menemukan bahwa pada pemasangan baru Buku Rantai Bukti belum punya berkas, sehingga alat auditor berhenti dengan "berkas tidak ditemukan". Kini buku yang dicatat titik periksa dengan 0 entri boleh belum punya berkas; buku yang sudah berisi tetapi berkasnya tidak ada tetap ditolak. 1 uji baru.
- **Batas:** entri sesudah titik periksa terakhir belum dilindungi; penghapusan kunci di SSD tidak dijamin tanpa enkripsi disk; kunci HMAC sendiri belum berevolusi.
- Versi 5.3.0 (`app/versi.py`); README, Proposal §5.5, Dokumentasi Teknis §2.7.1 dan §2.9, dek (slide 4 dan 5), poster diperbarui.

### Tautan repositori baru — 1 November 2026 (branch `feature/tautan-repo-v5.2`)
- Repositori berganti nama menjadi `Nusantara-Shield-v5.2`. Tautan di dek (slide 7 dan 8) dan poster ikut diganti; poster PDF/PNG dan slide PDF diekspor ulang. Tautan nama lama tetap dialihkan GitHub.

### Satu sumber versi dan nama peran berhuruf kapital — 30 Oktober 2026 (branch `feature/satu-sumber-versi`)
- **Masalah:** rilis v5.2.0 masih menampilkan "v5.1" di judul tab, subjudul dasbor, kop LAPSIT, dan nama zip, karena nomor versi ditulis langsung di beberapa berkas dan tidak ikut diganti.
- **Perbaikan:** nomor versi kini hanya ada di `app/versi.py` (`VERSI = "5.2.1"`).
  - Dasbor membacanya lewat label `nama_versi` di `GET /api/istilah`; kop LAPSIT mengimpornya langsung.
  - `tools/kemas_rilis.py` membacanya sebagai teks, sehingga zip rilis dan paket luring bernama `nusantara-shield-v5.2.1…`; versi bawaan paket Ubuntu ikut nilai yang sama.
  - `run_tests.sh` dan `run_tests.bat` mencetak versi dari berkas yang sama.
- **Nama peran:** header sesi, kolom peran di tab **Akun**, dan notifikasi kini menampilkan **Operator** dan **Pengamat** (label baru `peran_operator`, `peran_pengamat` di kamus istilah). Nilai teknis di API tetap huruf kecil (`operator`, `pengamat`), begitu pula nama akun bawaan. Kalimat di dasbor, pesan galat, README, Proposal, dan Dokumentasi Teknis ikut diseragamkan sesuai pedoman gaya.
- **5 uji baru** di `tests/test_versi.py`: label versi yang ditulis langsung di kode tampilan atau skrip uji → gagal; alat pengemas harus memakai nomor yang sama; nama peran tampil berhuruf kapital. Kamus istilah kini 40 uji (label `nama_versi`). Total **352 uji** dalam 18 kelompok.
- Dokumentasi Teknis §4.4: tabel kelompok uji dilengkapi baris Triase dan Kesiapan Siber (16) serta Paket pasang Ubuntu 24.04 (24), yang sebelumnya terlewat.
- Dek, poster, README, Proposal, dan Dokumentasi Teknis: label versi v5.2.1, jumlah uji 352, blok terminal dibuat ulang dari keluaran `./run_tests.sh` yang asli (352 passed in 43.97s).

### Wajib ganti sandi awal dan peta jalan studi banding — 30 Oktober 2026 (branch `feature/wajib-ganti-sandi`)
- **Wajib ganti sandi saat login pertama** (gagasan dari LogCrunch). `pasang.sh` kini menulis `NS_WAJIB_GANTI_SANDI=1` ke berkas env.
  - Sampai sandi awal diganti, akun bawaan hanya boleh memanggil loket ganti sandi dan keluar. Semua loket lain, termasuk siaran langsung, menjawab 403.
  - Loket baru `POST /api/akun/ganti-sandi` memeriksa sandi lama dan syarat sandi baru (min. 12 karakter, berbeda dari sandi lama, tanpa nama akun).
  - Loket itu dibatasi laju seperti *login*, mencabut sesi lain akun tersebut, dan mencatat `GANTI_SANDI` tanpa sandi.
  - Hash sandi pengganti akun bawaan disimpan di berkas akun, sehingga bertahan setelah *server* menyala ulang; sandi dari env tidak berlaku lagi.
  - Layar login menampilkan formulir **Ganti sandi awal**. Mode demo (tanpa bendera) tidak berubah.
- **9 uji baru** di `tests/test_akun.py` (bagian c), ditulis lebih dulu dan gagal sebelum implementasi. Ditambah satu pemeriksaan bendera di uji paket Ubuntu. Total **346 uji**.
- **Peta jalan penguatan dari studi banding arsitektur** (Proposal §5.5, Dokumentasi Teknis §2.9, slide 5, README):
  - evolusi kunci audit dan titik periksa Ed25519 (*forward security*, rujukan makalah Nitro ACM CCS 2025);
  - batas waktu *fail-safe* dan aturan dua orang (pola StackStorm dan Shuffle);
  - garis dasar Modbus (format pesan IPAL, RAID 2022; profil *polling* Welford);
  - paket intelijen bertanda tangan (pola Security Onion).
  - Semuanya belum dibangun. Dokumentasi Teknis §2.7 kini menyebut terus terang bahwa HMAC tidak melindungi dari pemegang kunci.
- **Panduan Belajar PDF** diekspor ulang: istilah Mesin Deteksi Aturan/Anomali, Mesin Asisten Narasi, dan Kepatuhan Pencadangan; jumlah uji 346 dalam 17 kelompok. Keterangan dua tangkapan layar lama yang masih memperlihatkan label "Server backup" sengaja dibiarkan sesuai gambarnya.

### Penyeragaman istilah — 30 Oktober 2026 (branch `feature/penyeragaman-istilah`)
- Pedoman gaya baru: istilah Indonesia didahulukan; istilah asli disebut sekali dalam kurung dan dicetak miring.
- **Engine Deteksi Aturan → Mesin Deteksi Aturan** (*rule-based detection engine*), **Engine Deteksi Anomali → Mesin Deteksi Anomali** (*anomaly detection engine*), dan Engine Asisten Narasi → Mesin Asisten Narasi.
  - Nama resmi masuk Kamus Istilah (`app/istilah.py`: `mesin_aturan`, `mesin_anomali`) sehingga terkunci oleh `test_istilah`.
- **Kepatuhan backup → Kepatuhan Pencadangan**. Label tab dan KPI dasbor kini dibaca dari kamus (`kepatuhan_pencadangan`).
- Teks *backup* yang tampil di layar, LAPSIT, *playbook*, dan log diganti *cadangan*/*pencadangan*. Contoh: tombol **Cadangkan + uji**, skenario **Cadangan mati**, kolom LAPSIT **Cadangan**, aset **Server cadangan**, langkah SOAR **Amankan cadangan**.
  - Kata *offline* pada baris yang sama menjadi *luring*.
  - Nama variabel, kunci data, dan alamat API (`jam_sejak_backup`, `/api/backup/catat`) tidak diubah supaya kompatibel.
- **337 uji** (sebelumnya 334): 3 label baru di uji kamus istilah.
- Saat contoh LAPSIT dibuat ulang, laporan rutin sempat melebar ke 2 halaman karena kata *cadangan* sedikit lebih panjang dari *backup*.
  - Alasan status dipadatkan: **Umur cadangan 52 jam (batas 24 jam)** dan **Cadangan ada, tetapi belum pernah diuji pulih**.
  - Uji laporan rutin kini mewajibkan "Halaman 1 dari 1", sehingga laporan yang melebar langsung tertangkap. Uji ini terbukti gagal sebelum perbaikan.
- Contoh LAPSIT (`docs/contoh-lapsit/`), poster, dan dek dibuat ulang.
- Tautan repo di dek dan poster diperbarui ke nama baru `Nusantara-Shield-v5.2.0`.
- Dokumen ikut diperbarui: README, Proposal, Dokumentasi Teknis (blok terminal dari `./run_tests.sh` asli), dek presentasi, dan poster.
- Catatan riwayat versi lama di bawah ini sengaja tidak diubah.

## v5.2.0 — 29 Oktober 2026

### Paket pasang luring bertanda tangan untuk Ubuntu 24.04 LTS (branch `feature/installer-ubuntu-ed25519`)
- **Target tetap:** Ubuntu 24.04 LTS, x86_64, Python 3.12 bawaan Ubuntu (`/usr/bin/python3.12`). Paket tidak membawa Python; bila syarat tidak terpenuhi, pemasang berhenti dengan kode 20 dan tidak mengubah apa pun.
- **`tools/kunci_rilis.py`** (komputer pembuat rilis): kunci Ed25519.
  - Kunci privat disimpan terenkripsi (PKCS#8, kata sandi minimal 16 karakter yang diketik, izin 600) di `~/.nusantara-shield/`, **di luar repo**.
  - Kunci tidak pernah ditimpa, dicetak, atau diterima sebagai argumen.
  - Setiap tanda tangan langsung diverifikasi ulang dengan kunci publik yang diterbitkan, dan dengan OpenSSL 3 bila ada.
- **`tools/kemas_installer.py`**: tiga langkah.
  1. `susun`: payload `.tar.gz` deterministik dari commit bersih, berisi kode, wheel Linux CPython 3.12 (`--only-binary`), `persyaratan-terkunci.txt` (versi + SHA-256 setiap wheel), dan `manifest.json` (SHA-256 setiap berkas).
  2. Penandatanganan `SHA256SUMS` dengan `kunci_rilis.py tandatangani`.
  3. `bungkus`: memeriksa tanda tangan lalu membuat `.tar` luar dan `SIDIK-JARI-PAKET-*.txt` untuk berita acara.
- **`installer/pasang.sh`** (POSIX sh, hanya alat bawaan Ubuntu):
  - memeriksa sidik jari kunci yang tertanam, tanda tangan Ed25519 (`openssl pkeyutl -verify -rawin`), dan `sha256sum -c --strict`;
  - memeriksa setiap anggota payload **sebelum ekstraksi** (tanpa jalur absolut/`..`/tautan/perangkat, harus tercatat di manifest);
  - mengekstrak ke folder sementara dengan filter `data`, lalu mencocokkan SHA-256 setiap berkas;
  - membuat venv `--without-pip` dan memasang pustaka dengan `pip --no-index --require-hashes`, lalu menjalankan uji asap `/api/health` (dan `--uji` untuk seluruh uji);
  - memasang pengguna `nshield`, env rahasia yang dibuat sekali, layanan systemd, dan pembungkus `ns-verifikasi-audit`;
  - mengganti tautan `kini` secara atomik. Ada `--kembali`, `--hapus` (env dan data dipertahankan), dan penolakan versi sama/turun.
- **`installer/nusantara-shield.service`**: pengguna tanpa login, `ProtectSystem=strict`, `NoNewPrivileges`, tanpa *capability*, `SystemCallFilter=@system-service`; hanya `/var/lib/nusantara-shield` yang boleh ditulis.
- **334 uji** (sebelumnya 310): 24 uji baru di `tests/test_paket_ubuntu.py`, kelompok ke-17.
  - Semua kunci uji dibuat sementara.
  - Ke-14 pemeriksaan pengaman di `pasang.sh` diuji mutasi (dijalankan pada salinan repo): setiap pemeriksaan dimatikan bergantian, dan sedikitnya satu uji gagal.
  - Uji argumen yang berjalan tanpa `--awalan` dibuat aman: tanda tangannya dibuang lebih dulu, sehingga seandainya pemeriksaan argumen rusak pun skrip berhenti sebelum mengubah sistem.
- `cryptography>=42` ditambahkan ke bagian pengujian/rilis `requirements.txt` (dipakai pembuat rilis dan uji; aplikasi tidak memakainya).
- **Diuji ujung ke ujung (kontainer Ubuntu 24.04, kunci uji sementara):**
  - paket dibuat dengan 36 wheel Linux asli (135 berkas, ±83 MB);
  - dipasang **sebagai root dengan jaringan diputus** (`unshare -n`): **333 passed** dari venv terpasang;
  - layanan dijalankan sebagai `nshield` dengan perintah dan env yang sama dengan berkas layanan: *login*, LAPSIT, dan `ns-verifikasi-audit` berhasil;
  - `--hapus` mempertahankan env dan data.
- **Belum diuji:** systemd sungguhan (kontainer tanpa systemd; berkas layanan baru diperiksa `systemd-analyze verify`). Rencananya diuji di VM Ubuntu pada QA akhir.
- Perbaikan setelah percobaan pertama di Mac: `kunci_rilis.py tandatangani` kini memeriksa berkas sebelum menanyakan kata sandi (sebelumnya sandi ditanyakan lalu gagal karena `SHA256SUMS` belum ada, sehingga terkesan sandi salah), dan `kemas_installer.py bungkus` memberi pesan jelas, bukan *traceback*, bila `susun` belum berhasil.
- Kunci publik rilis (`kunci/kunci-publik-rilis.pem`, sidik jari `00a223f1…240a`) ditambahkan; kunci privatnya hanya ada di Mac pembuat rilis.
- Dokumen: README (bagian paket Ubuntu dan kelompok uji ke-17), Dokumentasi Teknis §2.7 dan §4.4 (blok terminal dibuat ulang dari keluaran `./run_tests.sh` yang asli), Proposal, dek presentasi (slide 4: 17 kelompok), dan poster.

## v5.1 — 15–29 Oktober 2026

### Verifikasi audit tanpa server — 29 Oktober 2026 (branch `feature/verifikasi-audit-cli`)
- **`tools/verifikasi_audit.py`**: alat baris perintah untuk auditor yang memeriksa `data/audit_log.jsonl` dan `data/rantai_bukti.jsonl` **tanpa menyalakan server**. Hanya memakai pustaka bawaan Python, tidak mengimpor kode aplikasi, dan tidak membuka jaringan.
- Setiap entri dihitung ulang: nomor urut, mata rantai (`hash_sebelumnya`), dan HMAC-SHA256. Kerusakan pertama disebut letaknya.
- `--cocokkan <sidik jari>` memastikan sidik jari yang tercetak di LAPSIT ada di rantai, sehingga log yang dipotong di ujung (tidak terlihat oleh rantai saja) ikut ketahuan. Ada juga keluaran `--json`.
- Kode keluar 0/1/2. Kunci dibaca dari `NS_AUDIT_KEY` atau `--kunci-berkas`; tidak diterima sebagai argumen dan tidak pernah dicetak.
- Instruksi verifikasi di LAPSIT kini menyebut alat ini.
- **310 uji** (sebelumnya 298): 12 uji baru di `tests/test_verifikasi_audit.py`, kelompok ke-16. Ketiga pemeriksaan masing-masing terbukti diperlukan oleh uji mutasi: tiap pemeriksaan dimatikan bergantian, dan sedikitnya satu uji gagal.
- Dokumen ikut diperbarui ke 310 uji dalam 16 kelompok:
  - README (bagian *Verifikasi log audit tanpa menyalakan server*);
  - Proposal;
  - Dokumentasi Teknis, yang blok terminalnya dibuat ulang dari keluaran `./run_tests.sh` yang asli;
  - dek presentasi (slide 4 kini memuat 16 kelompok);
  - poster dan Panduan Belajar PDF.
- Contoh LAPSIT di `docs/contoh-lapsit/` dibuat ulang.
- Diuji ujung ke ujung dengan *server* berkunci sungguhan: sidik jari dari LAPSIT ditemukan di entri #6 (`EKSPOR_LAPSIT`). Setelah satu entri disunting, alat menunjuk entri #2 dan keluar dengan kode 1.
- Di Mac (macOS, Apple Silicon): 310 lulus. CLI juga berjalan dengan Python 3.9 bawaan macOS, tanpa pustaka tambahan.

### LAPSIT formal — 29 Oktober 2026 (branch `feature/lapsit-formal`)
- LAPSIT PDF disusun ulang seperti laporan insiden formal (gaya SANS/NIST SP 800-61), tujuh bagian, semuanya dari keadaan sistem saat dicetak:
  1. **Ringkasan eksekutif** naratif (apa, kapan, bagaimana, dampak);
  2. **Status layanan dan dampak operasional**, dengan profil misi dan kontinjensi per layanan (`DAMPAK_OPERASIONAL`, perkiraan);
  3. **Insiden dan tindakan**: kronologi gejala, langkah playbook dengan waktu eksekusi, T+detik, dan aktor, bukti SHA-256, MTTC, dan nomor laporan;
  4. **Tabel indikator kompromi (IoC)**: alamat ancaman skenario, alamat sumber temuan aturan, dan parameter Modbus (kode fungsi dan namanya);
  5. **Peringatan terbaru** (ATT&CK, sumber data);
  6. **Integritas log audit** dengan cara verifikasi untuk auditor;
  7. **Pengesahan**.
- Jejak langkah playbook kini mencatat **waktu (UTC) dan aktor**. Untuk tindakan SOAR berantai, aktornya adalah akun yang menahan tombol isolasi.
- Status IoC jujur: *Diblokir di firewall (simulasi)* hanya bila langkah pemutusnya sudah berjalan; sumber temuan aturan ditulis "tidak diblokir otomatis".
- Zona waktu laporan `NS_ZONA_WAKTU` (WIB/WITA/WIT, bawaan WIB).
- Uji LAPSIT yang ada diperluas untuk ketujuh bagian; jumlah uji tetap 298. Contoh PDF di `docs/contoh-lapsit/` dibuat ulang.

### LAPSIT berkop logo — 29 Oktober 2026 (branch `feature/lapsit-kop-logo`)
- **Kop di setiap halaman LAPSIT PDF**: logo Nusantara Shield digambar sebagai vektor langsung dari `static/logo.svg` (tanpa pustaka tambahan, tetap luring), identitas posko, nomor laporan `LAPSIT/NS/<tanggal-jam>`, waktu cetak, dan jenis laporan (*Laporan rutin* / *Laporan insiden (n aktif)*). Garis kop navy dan hijau sesuai warna merek.
- **Kaki halaman**: nomor laporan, keterangan dokumen latihan/data sintetis, dan "Halaman x dari y".
- Bila berkas logo tidak terbaca, LAPSIT tetap terbit tanpa logo (dikunci uji). Kop sengaja memakai identitas proyek sendiri, bukan kop surat atau lambang instansi.
- Uji LAPSIT yang ada diperluas (kop, jenis laporan, nomor halaman, logo dan cadangannya); jumlah uji tetap 298. Contoh PDF di `docs/contoh-lapsit/` dibuat ulang.

### Contoh LAPSIT PDF — 29 Oktober 2026 (branch `docs/contoh-lapsit`)
- `docs/contoh-lapsit/`: dua LAPSIT PDF yang diekspor dari aplikasi v5.1.3 (commit d1fbfdc) dengan data sintetis — kondisi normal (laporan rutin, 1 halaman) dan setelah latihan insiden (2 halaman) — beserta cara membuatnya ulang. Juri bisa melihat keluaran tanpa memasang aplikasi.
- README: baris *LAPSIT kapan saja* di tabel doktrin.

### Panduan Belajar diperbarui untuk Fase 2–3 — 27 Oktober 2026 (branch `docs/panduan-fase2-3`)
- `docs/03-Panduan-Belajar-Nusantara-Shield.pdf` (62 halaman): Bab 7 menambah *Aturan OT, label MITRE ATT&CK, dan label sumber data* (termasuk pengesahan dua tanda tangan LAPSIT) serta *Impor log luring*; Bab 9 menambah *Lisensi: GNU GPL v3.0*; jumlah uji diperbarui menjadi 298 dalam 15 kelompok.

### Fase 3: impor log luring — 27 Oktober 2026 (branch `feature/fase3-impor-log`)
- **Impor log asli** lewat tombol *Impor log…* di bilah Latihan (Operator saja) dan `POST /api/deteksi/impor`. Format: log autentikasi OpenSSH (auth.log/secure/journal), log firewall UFW/iptables (`SRC=`, `DST=`, `DPT=`), dan CSV berkepala `waktu,jenis,sumber,…`. Modul `app/impor_log.py` hanya menyalin baris relevan menjadi peristiwa mentah; **aturan yang menilainya sama persis dengan aturan latihan**.
- Validasi ketat: IP, *port*, fungsi Modbus, jam, dan aset diperiksa; baris tidak sah dilewati dan dihitung; berkas tak dikenali ditolak 422. Maks. ±2 MB dan 50.000 baris.
- Hanya jalur impor yang boleh menerima kiriman sampai ±2,6 MB, dan hanya bila membawa token (tanpa token: 401 sebelum body dibaca). Jalur lain tetap 16 KB. Dibatasi 6 kali per menit.
- Privasi: nama akun dalam log tidak disalin; log audit hanya mencatat nama berkas, jumlah baris, dan jumlah temuan.
- Dua kunci tetap: temuan dari log asli hanya menaikkan WASPADA, dengan label "Sumber: log impor «nama berkas» dari Operator".
- Contoh berkas sintetis di `docs/contoh-log/`. Baris terminal dek slide 4 dipadatkan agar 15 kelompok uji muat.
- **298 uji** (sebelumnya 280): 18 uji baru di `tests/test_impor_log.py`.

### Lisensi GPLv3 dan penanda hak cipta — 27 Oktober 2026 (branch `chore/lisensi-gplv3`)
- Berkas **`LICENSE`**: teks resmi GNU GPL v3.0 tanpa diubah (SHA-256 `3972dc97…986`).
- Setiap berkas kode (`app/`, `tools/`, `static/*.js`, skrip `.sh`) diberi penanda `SPDX-License-Identifier: GPL-3.0-only` dan hak cipta "Copyright (c) 2026 Nusantara Shield Team. Dikembangkan untuk Kartika Cyber Hackathon 2026."
- README dan Proposal §6.3 menjelaskan lisensi; rujukan kerangka pindah ke §6.4.

### Fase 2: aturan OT, label MITRE ATT&CK, label sumber data, pengesahan LAPSIT — 27 Oktober 2026 (branch `feature/fase2-mitre-ot-lapsit`)
- **Aturan OT deterministik** di Engine Deteksi Aturan: koneksi IT ke zona kendali OT dari alamat yang tidak terdaftar (tinggi, 0,50), perintah tulis Modbus di luar jendela pemeliharaan 22.00–02.00 (kritis, 0,70), dan rantai keduanya dari alamat yang sama dalam 600 detik (kritis, 0,90). Jalur resmi dan perintah baca bukan temuan. **Dua kunci tetap:** temuan hanya menaikkan pengendali genset ke WASPADA; tidak ada insiden, bukti, atau isolasi yang terpicu. Latihan baru **Akses OT tanpa izin** di bilah latihan.
- **Label MITRE ATT&CK®** (`app/mitre.py`, luring) di tabel Peringatan terbaru, log peristiwa, dan LAPSIT: T1110, T1078, T1046, T1486, T1490, T1498, serta ATT&CK for ICS T0886 dan T0855. AI lokal sengaja tanpa label.
- **Label batasan** di setiap peringatan: sumber datanya dan apa yang masih simulasi.
- **LAPSIT PDF:** bagian baru *Peringatan terbaru* (dengan teknik ATT&CK dan sumber data) dan blok **pengesahan dua tanda tangan** (Operator jaga; Mengetahui, pejabat siber/komandan dari kamus istilah). Judul dan kotak tanda tangan tidak terpisah halaman; nama layanan panjang tidak lagi menimpa kolom status. LAPSIT kini memproses peristiwa deteksi yang sudah jatuh tempo sebelum dicetak.
- Kalimat pembeda di catatan pembicara slide 3 dan 5, judul Lampiran B, dan README.
- **280 uji** (sebelumnya 254): 23 uji baru di `tests/test_ot_mitre_lapsit.py`, 3 uji kamus istilah baru. Blok terminal di Dokumentasi Teknis §4.2 dibuat ulang dari jalannya uji yang sebenarnya.

### Peta kriteria penilaian dan asal angka — 27 Oktober 2026 (branch `docs/peta-kriteria-asal-angka`)
- **Proposal §7:** peta lima kriteria Rulebook (bagian H) ke bukti di karya dan cara memeriksanya, serta tabel **asal setiap angka** (berkas, uji, atau alat ukur), termasuk batas tiap angka. Contoh: ±1,2 detik adalah jeda baku alur purwarupa (`JEDA_RUNBOOK`), bukan waktu sakelar fisik.
- **Dek:** slide baru **Lampiran B · Peta Kriteria dan Asal Angka** (dek kini 8 slide); kalimat pembeda di catatan pembicara slide 2 dan 6.
- Ringkasan Eksekutif Proposal dan README memuat kalimat pembeda: sistem berlanjut dari alarm sampai bukti tersegel, jalur terputus, dan LAPSIT terbit, tanpa internet.
- Waktu menjalankan uji diperbarui sesuai pengukuran nyata (±30 detik di Mac, ±55 detik di Linux).
- `.gitignore` menolak catatan internal tim (folder `catatan-internal/`, `Belanja Masalah/`, dan berkas berlabel OSINT).

### Spanduk halaman depan — 27 Oktober 2026 (branch `docs/banner-readme`)
- README dibuka dengan spanduk lebar: simbol, nama, tiga kata kerja Penangkalan, dan keterangan lomba. Disertakan juga `social-preview.png` (1280 × 640) untuk pratinjau tautan GitHub.

### Logo resmi dan penyesuaian Rulebook — 27 Oktober 2026 (branch `docs/rulebook-logo-v2`)
- **Logo Nusantara Shield** menggantikan logo generik di dasbor (beserta favicon), dek presentasi, dan poster: perisai, Merah Putih 3:2, radar dua cincin, Nusantara, dan ancaman yang terkunci di perimeter. Berkas, makna, dan aturan pemakaian ada di `docs/logo/`. Poster kini mengambil logo langsung dari `docs/logo/simbol.svg`.
- **Rujukan aturan** di Proposal, Dokumentasi Teknis, dan riwayat ini diganti dari "pasal 5.3/5.4 Syarat dan Ketentuan" ke **Rulebook bagian G (Ketentuan Karya)**, karena Rulebook terbaru tidak lagi memakai nomor pasal. Isi deklarasi tidak berubah.
- **Atribusi** ditambah Gemini (eksplorasi awal konsep logo) dan huruf Inter (OFL) untuk logo horizontal.
- **Dek:** slide Lampiran kini memuat tautan ke repositori dan folder `docs/`, karena dokumentasi teknis tidak lagi diserahkan sebagai berkas terpisah tetapi tetap dinilai.

### Susunan tim di Proposal — 26 Oktober 2026 (branch `docs/nama-tim`)
- Baris **Tim** di Proposal diisi: Muhammad Isa Ananta · Hasan Basri · Melia Fajar Hasanah (sebelumnya masih *placeholder*).

### Tata letak penuh: tanpa ruang kosong di monitor posko — 26 Oktober 2026 (branch `feature/tata-letak-penuh`)
- **Baris Radar | Aset | Beban disamakan tingginya.** Ruang kosong di dalam panel turun dari ±300–580 px menjadi 1 px (diukur di 1440, 1920, dan 2880 px). Ruang lebih dipakai isi: kartu aset merata, dan linimasa 60 menit membesar dengan garis ambang waspada/kritis yang diambil dari *server*.
- **Peringatan terbaru menjadi tabel lebar penuh**: keparahan, peringatan, aset, status, waktu, satu baris per peringatan. Di ponsel, tabel berubah menjadi kartu bertumpuk.
- **Latihan menjadi satu bilah alat mendatar** (target, 4 skenario, latihan deteksi).
- **Pita anomali AI** dibatasi 3 (yang berlangsung lebih dulu), dengan tombol "+N aset lainnya".
- **Rel keputusan setinggi layar.** Log mengisi sisa ruang dan digulir di dalam, sehingga ±880 px kosong di bawah rel (1920 px) hilang. Mode ringkas Log kini memotong tiap entri menjadi 2 baris, bukan menyembunyikannya.
- **Executive Overview:** Postur dan Kesiapan ditumpuk di kiri, 6 KPI (3 × 2) di kanan, sehingga tidak ada kartu setengah kosong.
- **Monitor 1280–1679 px:** Radar dan Aset berdampingan, Beban Jaringan selebar baris (meteran di kiri, linimasa di kanan).
- **Layar sangat lebar atau di-*zoom out*:** isi melebar sampai 2.400 px, dan bilah judul berbagi tepi yang sama dengan isi.
- Hanya HTML, CSS, dan JavaScript tampilan; logika *server* tidak berubah. 254 uji lulus. Tanpa galat konsol. Ponsel 390 px tanpa gulir samping. Tombol latihan tetap nonaktif untuk Pengamat.
- README dan Panduan (PDF serta Claude Docs) diperbarui untuk letak Peringatan terbaru yang baru.

### Dokumentasi akhir: tiga kata kerja, deteksi, linimasa, angka terukur ulang — 26 Oktober 2026 (branch `docs/deteksi-linimasa-tiga-kata-kerja`)
- Paragraf pembuka Proposal, Dokumentasi Teknis, README, dek, poster, dan Panduan kini menempatkan Nusantara Shield sebagai perisai pertahanan (*Defensive Shield*) dengan tiga kata kerja: **mendeteksi**, **mencegah**, dan **membantu merespons**. Respons ditulis "otomatis setelah satu keputusan Operator", dengan catatan bahwa perintah ke perangkat masih simulasi.
- Engine Deteksi Aturan didokumentasikan dengan ambang yang dikunci uji (8 gagal/60 dtk, tembus ≤ 120 dtk, 15 kombinasi/10 dtk, aktif 300 dtk), di Dokumentasi Teknis §2.8 yang baru dan Panduan Bab 7. Ikut didokumentasikan: linimasa 60 menit berlabel data latihan, pita anomali AI, serta KPI MTTC dan insiden.
- Jumlah uji 224 → **254** di semua dokumen; cuplikan terminal dari keluaran asli (`254 passed in 33.82s`).
- CPU: angka versi akhir **±1,5% siaga, ±1,7% serangan** untuk 300 layar (`tools/ukur_beban.py`, Linux 2 inti). Angka 10,8% → 2,8% tetap dicatat sebagai riwayat optimasi siaran ralat (17 Okt), dengan keterangan bahwa alat dan mesinnya berbeda, sehingga tidak dibandingkan langsung.
- NIST CSF: DE.CM dan DE.AE kini memuat aturan deteksi; peristiwa identitas nyata dari Active Directory tetap peta jalan.
- Peta jalan baru: **respons bertingkat menurut kritikalitas aset**. Aset vital tetap dua kunci; *endpoint* kantor berisiko rendah dapat diisolasi otomatis dengan *playbook* praotorisasi.
- Poster dan PDF Panduan dibangun ulang; tanpa perubahan kode aplikasi.

### Linimasa 60 menit, pita anomali AI, dan KPI posko — 26 Oktober 2026 (branch `feature/timeline-ai-kpi`)
- Panel Beban Jaringan: grafik 48 detik diganti **linimasa 60 menit** (60 titik × 1 menit, ditambah menit berjalan) berlabel **"data latihan"**. Saat posko baru dibuka, 60 menit sebelumnya diisi data latihan bangkitan berbenih tetap (batang redup, tanpa insiden dan tanpa anomali karangan); setiap 60 detik beban posko yang sebenarnya menjadi satu titik baru. Menit yang memuat insiden diberi tanda merah.
- **Pita anomali AI per aset** di bawah linimasa: nama aset, lama anomali, alasan dari model, dan penanda "berlangsung". Pita hanya lahir dari penilaian AI di sesi ini. Klik pita untuk menyorot aset itu di topologi.
- KPI baru: **Waktu respons (MTTC)**, yaitu rata-rata dari insiden dimulai sampai langkah penahanan selesai, dan **Insiden sejak posko aktif**. Keduanya dihitung dari kejadian yang tercatat, lalu dimulai ulang saat demo diatur ulang.
- `tools/ukur_beban.py` (baru): pengukur beban yang dapat diulang. Alat ini menyalakan *server*, membuka N siaran SSE sungguhan, lalu mencatat waktu CPU proses *server*. Hasil untuk 300 layar di Linux 2 inti (Python 3.13), metode dan mesin sama: sebelum PR ini 1,43% (tenang) dan 1,60% (serangan); sesudahnya **1,47%** dan **1,67%**, dengan 300/300 siaran tetap hidup. Lalu lintas siaran naik dari 0,25–0,33 menjadi 0,28–0,40 MB/s karena linimasa ikut dikirim sekali per menit. Angka 2,8% di dokumen lama diukur dengan skrip yang tidak tersimpan di repositori, jadi tidak dibandingkan langsung.
- 6 uji baru (`tests/test_linimasa.py`); 254 uji lulus.

### Engine deteksi aturan: login gagal berulang dan pemindaian port — 26 Oktober 2026 (branch `feature/deteksi-login-portscan`)
- `app/deteksi.py` (baru): aturan deteksi **sungguhan** yang membaca peristiwa mentah sintetis (percobaan login, koneksi masuk), bukan baris log yang disuntikkan. Ambang terbuka di kode: **≥ 8 login gagal dari satu IP dalam 60 dtk** (sedang); **login berhasil ≤ 120 dtk setelah rentetan itu** (tinggi); **≥ 15 kombinasi aset:port berbeda dari satu IP dalam 10 dtk** (tinggi). Temuan aktif 300 dtk sejak peristiwa terakhir; rentetan yang berlanjut tidak menggandakan temuan.
- Temuan menjadi sumber ketiga prediksi (`DET-…`) di samping CTI dan AI, digabung dengan noisy-OR yang sama. Dua kunci tidak berubah: deteksi hanya menaikkan aset ke WASPADA; isolasi tetap keputusan Operator. Perketat memotong sumbangannya; triase dapat menutupnya. Aset yang sedang ditangani *playbook* insiden tidak dinilai ulang dan diberi label jujur "Aset ditangani lewat playbook insiden".
- Panel **Peringatan terbaru**: label status diambil dari data sebenarnya, misalnya "Diisolasi oleh operator · bukti BB-2026-001" (nama Operator dan nomor berita acara bukti yang tercatat), bukan teks tetap.
- Latihan deteksi (Operator saja): `POST /api/deteksi/latihan` memutar rangkaian peristiwa sintetis berlabel (IP dokumentasi RFC 5737); tercatat di log audit.
- 24 uji baru (`tests/test_deteksi.py`), termasuk uji yang mengunci ambang terdokumentasi dan uji waktu (gagal ke-7 belum, ke-8 terdeteksi). Uji mutasi: mengubah ambang kini menggagalkan 3 uji. 248 uji lulus.

### Sistem pendukung keputusan, NIST CSF 2.0, dan keamanan posko — 26 Oktober 2026 (branch `docs/spk-nist-keamanan-posko`)
- Pembingkaian **sistem pendukung keputusan (SPK)** di Proposal, Dokumentasi Teknis, dek, dan Panduan: mesin mempercepat, manusia memutuskan. Alasan sengaja **tidak** otonom penuh dituliskan: peringatan keliru yang memutus layanan sendiri, respons yang dapat dipancing pihak luar, dan pemutusan tanpa pejabat yang bertanggung jawab.
- Dokumentasi Teknis §2.6: pemetaan fitur ke **NIST CSF 2.0** (CSWP 29) per kategori, dengan status (berjalan, simulasi, peta jalan) dan berkas uji yang membuktikannya. Pemetaan mandiri, bukan sertifikasi.
- Dokumentasi Teknis §2.7: **keamanan posko itu sendiri**, berupa tabel ancaman → pengamanan → uji, beserta batasnya (HTTPS lewat *proxy* balik, sesi di memori, belum ada verifikasi dua langkah, belum ada uji penetrasi independen, syarat saat tersambung ke perangkat nyata).
- Peta jalan: pemantauan peristiwa identitas (Active Directory) dan pengamanan integrasi nyata (brankas kredensial, hak minimum per *playbook*, *playbook* bertanda tangan, persetujuan dua orang).
- `docs/poster/`: poster satu halaman A4 (HTML, PDF, PNG); setiap butir berlabel BERJALAN, SIMULASI, atau PETA JALAN. Bendera Merah Putih, ikon Lucide (ISC) sebagai SVG sebaris pada metrik, alur, enam fungsi CSF, dan jenis aset, ilustrasi jaringan abstrak, baris format laporan siap lapor (bahan pelaporan ke BSSN dan UU PDP; belum diaudit kepatuhan), dan peta jalan "Integrasi Direktori Aktif (IAM) & Pemantauan Login". Sumber dan pembangkitnya di `docs/poster/sumber/`.
- Tanpa perubahan kode aplikasi; 224 uji lulus.

### Perbaikan uji paket lintas-OS — 26 Oktober 2026 (branch `fix/uji-paket-lintas-os`)
- `test_kebutuhan_lintas_sistem_operasi_disesuaikan_target` kini memakai `requirements.txt` contohnya sendiri. Sebelumnya uji membaca berkas di folder tempat ia dijalankan, sehingga **gagal di dalam paket luring lintas-OS** (misalnya paket Mac yang dibuat di Linux), karena di sana `uvicorn[standard]` memang sengaja diganti `uvicorn` polos. Ditemukan saat paket Mac dipasang langsung di Mac.
- Zip dibangun dari salinan kerja yang izin berkasnya sudah dinormalkan (644/755). Sebelumnya 9 berkas berizin baca-saja (444) ikut terbawa ke zip; di Mac (`ditto`/Finder) izin itu dipertahankan dan membuat satu uji gagal menulis `requirements.txt`.
- Tanpa perubahan kode aplikasi; 224 uji lulus.

### Tata posko 24 jam — 23 Oktober 2026 (branch `feature/ui-posko-24jam`)
- **Rel keputusan** di kanan layar (≥ 1280 px), lengket saat digulir: Action Center → Prediksi CTI + AI → Log. Di monitor 1920×1080, tombol Eksekusi Isolasi kini terlihat tanpa menggulir (sebelumnya di bawah lipatan layar, y ≈ 1.076 px). Insiden baru mengembalikan rel ke Action Center.
- Layar sempit: satu kolom; selama ada insiden yang belum diisolasi, Action Center naik ke paling atas.
- Gerak hanya untuk yang tidak normal: arus topologi normal diam (redup), hanya arus waspada/kritis yang bergerak; kedip keras 1 Hz diganti denyut lembut 2,4 dtk; tombol Isolasi tidak lagi berdenyut tanpa henti. Animasi tak henti saat tenang: 13 → 2.
- Satu skala warna keparahan: warna yang ditulis langsung (#ff9a6b, #ff9f5a, #c9d36b, #8fe3b4) menjadi token; peluang "sedang" (di bawah ambang) netral, kuning disimpan untuk WASPADA; kartu prediksi WASPADA disorot.
- Kontras: `--teks-samar` 3,0–3,5:1 → ≥ 4,6:1 (WCAG AA); pendar dekoratif (latar, logo, judul panel, panel kritis, meteran) dihapus; huruf label minimum ±10,5 px.
- Panduan radar dilipat bawaan; Action Center saat SIAGA cukup satu baris.
- Hanya `static/` (HTML, CSS, 3 baris JS); backend tidak berubah; 224 uji tetap lulus.

### Kesiapan Siber dan triase — 22 Oktober 2026 (branch `feature/kesiapan-dan-triase`)
- Kartu **Nilai Kesiapan Siber** A–E di Executive Overview: dua sub-skor (Kerawanan, Insiden) per layanan, nilai posko tertimbang jumlah aset; rumus terbuka di `app/telemetri.py` dan Dokumentasi Teknis §2.5.
- **Triase peringatan**: Operator menutup peringatan WASPADA sebagai Selesai ditangani atau Positif Palsu (*False Positive*) dengan alasan tertulis (`POST /api/peringatan/tutup`). Penutupan menjadi halaman `PERINGATAN_DITUTUP` di Buku Rantai Bukti; tidak ada yang dihapus, dan bukti baru membuka peringatan lagi.
- 16 uji baru (+4 uji kamus untuk label baru); total 224 uji dalam 11 kelompok.

### Penajaman narasi — 22 Oktober 2026 (branch `docs/penajaman-narasi`)
- "Dua kunci konfirmasi" ditulis eksplisit di Proposal, Dokumentasi Teknis, dan dek: CTI dan AI lokal hanya menaikkan WASPADA; isolasi hanya bisa diperintahkan Operator (Pengamat ditolak 403, dikunci uji yang sudah ada).
- Pelajaran PDNS 2024 dikaitkan ke Mode Berdaulat: inti pertahanan berjalan di posko sendiri, tidak bergantung pada pusat data atau awan.
- Dokumentasi Teknis: daftar komponen (FastAPI, scikit-learn, HMAC-SHA256 bawaan Python) dan subbab 1.4 Data Latihan Sintetis (RFC 5737, RFC 2606, EICAR).
- Rujukan ISO/IEC 27037:2012 ("mengikuti prinsip", belum diaudit) di Proposal, Dokumentasi Teknis, dan Panduan; kotak Batasan Penggunaan (UU ITE, UU PDP) di Panduan.
- Tanpa perubahan kode; 204 uji tetap lulus.

### Paket pasang luring — 22 Oktober 2026
- `tools/kemas_luring.py` membundel kode dan semua pustaka (`pip download`) beserta daftar sidik jari `SHA256SUMS`; `pasang_luring.py` memeriksa sidik jari lalu memasang dengan `pip install --no-index`, tanpa internet.
- 8 uji baru; total 204 uji.

### Narasi penangkalan — 22 Oktober 2026
- Alur cerita dokumen dan dek dibuka dengan peringatan dini (CTI + AI lokal → WASPADA → Perketat), lalu isolasi ±1,2 detik bila ancaman tetap tembus.

### Finalisasi hackathon — 20 Oktober 2026 (branch `feature/finalisasi-hackathon`)
- Skrip pembuatan ulang `.venv` setelah folder proyek dipindah (`tools/perbaiki_venv.sh`).
- Nama enam aset contoh disesuaikan dengan konteks RS dan markas TNI AD; ID, IP, *port*, dan logika deteksi tidak berubah.
- Istilah SITREP diganti LAPSIT di kode dan antarmuka: `app/sitrep.py` → `app/lapsit.py`, rute `/api/sitrep` → `/api/lapsit`. Kata "peladen" diganti *server*.
- Dokumen: penyisiran PUEBI, tabel status fitur (sudah berjalan vs peta jalan), dua pilar AI (Engine Deteksi Anomali berjalan; Engine Asisten Narasi Llama 3 8B masih peta jalan).

### AI lokal — 20 Oktober 2026
- Engine Deteksi Anomali: *Isolation Forest* (scikit-learn), dilatih dan dijalankan luring di *server*; skornya digabung dengan peluang CTI; disertai alasan yang bisa dibaca.
- 10 uji khusus AI; total 196 uji.

### Fase 7 — 20 Oktober 2026
- Aset rumah sakit, skenario Sabotase OT (isolasi jalur kantor → zona kendali), istilah satuan.

### Fase 6 — 20 Oktober 2026
- Aset OT pertama: pengendali genset (Modbus/TCP, *port* 502); uji OT (`tests/test_ot.py`).

### Fase 5 — 18 Oktober 2026
- Tujuh perbaikan hasil audit; manajemen akun (`tests/test_akun.py`).
- `docs/` (diagram alur), `pytest.ini`, `run_tests.sh`/`run_tests.bat`, `tools/kemas_rilis.py`.

### Fase 4 — 18 Oktober 2026
- Rantai bukti forensik: `app/bukti.py`, sidik jari SHA-256, Buku Rantai Bukti HMAC; `tests/test_rantai_bukti.py`.

### Fase 3 — 17 Oktober 2026
- Siaran ralat (delta) `app/delta.py` dan penjadwal layar `static/penjadwal.js`: CPU *server* 10,8% → 2,8% dan lalu lintas −80% untuk 300 layar.

### Fase 2 — 17 Oktober 2026
- Pembaruan *server*, keamanan, dan telemetri beserta ujinya.

### Fase 1 — 16 Oktober 2026
- Penyesuaian istilah dari korporat ke istilah Pussiber AD (kamus istilah).

## v5.0 — 16 Oktober 2026
- Penyempurnaan *server*, dasbor, dan uji (CTI/SOAR, komando, telemetri).

## v4.0 — 16 Oktober 2026
- Rantai komando dan laporan (`tests/test_komando.py`).

## v3.0 — 16 Oktober 2026
- Peta Global (`static/peta.js`), korelasi CTI dan SOAR (`tests/test_cti_soar.py`).

## v2.0 — 16 Oktober 2026
- Arsitektur klien–*server*: dapur situasi (`app/telemetri.py`), Radar Anomali (`static/radar.js`), siaran langsung SSE; `tests/test_telemetri.py`.

## v1.0 — 15 Oktober 2026
- *Server* FastAPI, dasbor awal, login dan peran (`app/keamanan.py`), log audit berantai HMAC (`app/audit.py`), ekspor laporan situasi ke PDF, data contoh sintetis; `tests/test_keamanan.py`.
