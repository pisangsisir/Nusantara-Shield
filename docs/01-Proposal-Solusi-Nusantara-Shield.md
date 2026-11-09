# Proposal Solusi — Nusantara Shield v5.4.0

**Posko Pertahanan Siber Luring: Peringatan Dini, Isolasi Cepat, dan Rantai Bukti Forensik**

| | |
| --- | --- |
| **Kompetisi** | Kartika Cyber Hackathon 2026 · Pusat Siber Angkatan Darat (Pussiberad) × CODEPOLITAN |
| **Kategori** | 02 · **Penangkalan (_Defensive Shield_)** — *Threat Intelligence Platform* dan *Automated Incident Response* |
| **Tim** | Muhammad Isa Ananta · Hasan Basri · Melia Fajar Hasanah |
| **Status purwarupa** | **Berfungsi penuh** · 411 uji otomatis lulus · AI deteksi anomali dan aturan deteksi berjalan lokal · luring tanpa internet |
| **Tanggal** | 27 Oktober 2026 |

---

## 1. Ringkasan Eksekutif

> ### Nusantara Shield: perisai pertahanan (_Defensive Shield_) luring yang **mendeteksi**, **mencegah**, dan **membantu merespons** serangan siber: memperingatkan lebih dulu, memutus dalam 1,2 detik, dan tidak pernah menghapus barang bukti.

> **Serangan siber tidak menunggu rapat staf.** _Ransomware_ mengenkripsi satu _server_ per menit, sementara posko siber masih memilah ratusan peringatan, menunggu izin berjenjang, dan menyusun laporan dengan tangan. Saat jaringan akhirnya diputus atau dipulihkan, jejak penyerang sering sudah terhapus.

**Nusantara Shield** adalah perisai pertahanan siber (kategori **Penangkalan, _Defensive Shield_**) dan **sistem pendukung keputusan (SPK)** bagi posko satuan, ibarat **Perwira Staf Siber Digital**. Ia bekerja dengan tiga kata kerja: **mendeteksi** ancaman (aturan deteksi, AI lokal, dan kabar ancaman), **mencegah** aset berisiko diserang (WASPADA dan Perketat), dan **membantu merespons** dengan urutan baku yang berjalan otomatis setelah satu keputusan Operator. Ia menjaga **jaringan perkantoran (IT)** dan **sistem kendali fasilitas (OT)** dalam satu layar. Ia mengamati tanpa henti, mencocokkan setiap kabar ancaman dengan aset milik satuan sendiri, dan menyajikan langkah penindakan yang sudah dibakukan dalam doktrin. **Keputusan tetap di tangan manusia.** Begitu Operator menahan tombol, sistem menjalankan urutan baku secara otomatis (di purwarupa, perintah ke perangkat jaringan masih simulasi):

Nusantara Shield bekerja dalam **dua lapis**:

1. **Lapis pertama: deteksi dan tangkal lebih dulu.** Kabar ancaman (CTI), AI lokal, dan aturan deteksi (_login_ gagal berulang, pemindaian _port_) menaikkan aset IT maupun OT yang berisiko ke **WASPADA** sebelum diserang. Satu klik **Perketat** menurunkan paparannya. Contoh terukur: kabar celah Modbus menaikkan pengendali genset ke peluang ≈66%, dan Perketat menurunkannya ke ≈20%.
2. **Lapis kedua: bila ancaman tetap tembus, bukti dulu, baru putus.** Begitu Operator memutuskan, _server_ menjalankan alur baku di bawah dalam urutan yang tidak bisa dilompati.

> **Dua kunci konfirmasi sebelum jaringan diputus.** Kunci pertama dipegang mesin: kabar ancaman (CTI) dicocokkan dengan aset satuan, AI lokal menilai lalu lintasnya, dan aturan deteksi menghitung peristiwa _login_ serta koneksi masuk, tetapi hasilnya hanya menaikkan status ke WASPADA. Kunci kedua dipegang manusia: hanya akun Operator yang dapat memerintahkan isolasi, dengan menahan tombol 0,6 detik; permintaan dari akun Pengamat ditolak _server_. **Tidak ada satu sinyal pun yang memutus jaringan vital secara otomatis penuh (_autonomous_) tanpa keputusan akhir manusia.**

<div class="ilustrasi" id="ilustrasi-alur">
<svg viewBox="0 0 1000 190" width="100%" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Alur baku Nusantara Shield: amankan bukti, isolasi IT dan OT, laporkan, pulihkan; urutan dikunci server"><rect width="1000" height="190" rx="10" fill="#0d1729"/><text x="24" y="30" font-family="ui-monospace,Menlo,Consolas,monospace" font-size="13" font-weight="700" letter-spacing="2" fill="#3ef0a1">ALUR BAKU · DIKUNCI DI SERVER</text><text x="976" y="30" text-anchor="end" font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif" font-size="12" fill="#8798b1">Operator cukup menahan satu tombol 0,6 detik</text><rect x="24" y="50" width="220" height="96" rx="9" fill="#111d33" stroke="#7aa2d6" stroke-width="2"/><text x="40" y="78" font-family="ui-monospace,Menlo,Consolas,monospace" font-size="13" font-weight="700" fill="#7aa2d6">01</text><text x="70" y="78" font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif" font-size="15" font-weight="700" fill="#ffffff">AMANKAN BUKTI</text><text x="40" y="106" font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif" font-size="13" fill="#d7e3f2">Memori, log, trafik</text><text x="40" y="126" font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif" font-size="13" fill="#d7e3f2">disegel SHA-256</text><path d="M248 98 L270 98" stroke="#8798b1" stroke-width="2"/><path d="M270 92 L276 98 L270 104 Z" fill="#8798b1"/><rect x="274" y="50" width="220" height="96" rx="9" fill="#111d33" stroke="#ff5c74" stroke-width="2"/><text x="290" y="78" font-family="ui-monospace,Menlo,Consolas,monospace" font-size="13" font-weight="700" fill="#ff5c74">02</text><text x="320" y="78" font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif" font-size="15" font-weight="700" fill="#ffffff">ISOLASI IT · OT</text><text x="290" y="106" font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif" font-size="13" fill="#d7e3f2">≈1,2 dtk sejak keputusan Operator</text><text x="290" y="126" font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif" font-size="13" fill="#d7e3f2">genset tetap menyala</text><path d="M498 98 L520 98" stroke="#8798b1" stroke-width="2"/><path d="M520 92 L526 98 L520 104 Z" fill="#8798b1"/><rect x="524" y="50" width="220" height="96" rx="9" fill="#111d33" stroke="#f5c451" stroke-width="2"/><text x="540" y="78" font-family="ui-monospace,Menlo,Consolas,monospace" font-size="13" font-weight="700" fill="#f5c451">03</text><text x="570" y="78" font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif" font-size="15" font-weight="700" fill="#ffffff">LAPORKAN</text><text x="540" y="106" font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif" font-size="13" fill="#d7e3f2">LAPSIT otomatis</text><text x="540" y="126" font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif" font-size="13" fill="#d7e3f2">ke pimpinan</text><path d="M748 98 L770 98" stroke="#8798b1" stroke-width="2"/><path d="M770 92 L776 98 L770 104 Z" fill="#8798b1"/><rect x="774" y="50" width="220" height="96" rx="9" fill="#111d33" stroke="#3ef0a1" stroke-width="2"/><text x="790" y="78" font-family="ui-monospace,Menlo,Consolas,monospace" font-size="13" font-weight="700" fill="#3ef0a1">04</text><text x="820" y="78" font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif" font-size="15" font-weight="700" fill="#ffffff">PULIHKAN</text><text x="790" y="106" font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif" font-size="13" fill="#d7e3f2">Terkunci sampai</text><text x="790" y="126" font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif" font-size="13" fill="#d7e3f2"><tspan font-style="italic">hash</tspan> cocok ulang</text><rect x="24" y="160" width="952" height="0" /><text x="24" y="172" font-family="system-ui,-apple-system,Segoe UI,Roboto,sans-serif" font-size="12.5" fill="#ff8a9c">✕ Isolasi tanpa bukti atau pemulihan sebelum <tspan font-style="italic">hash</tspan> cocok: ditolak <tspan font-style="italic">server</tspan> (409). Setiap langkah tercatat di buku berantai HMAC.</text></svg>
<p class="keterangan"><em>Alur baku Nusantara Shield. Begitu Operator memutuskan, server menjalankan empat langkah ini dalam urutan yang tidak bisa dilompati.</em></p>
</div>

Setiap langkah tercatat permanen dalam buku berantai Hash-based Message Authentication Code (HMAC) yang tidak bisa diubah diam-diam.

**Hasilnya, postur pertahanan bergeser dari reaktif menjadi proaktif.**

- **Ancaman terlihat lebih awal.** Aset berisiko dinaikkan ke status *waspada* sebelum diserang, baik karena kabar ancaman (CTI), karena **AI lokal** menilai lalu lintasnya tidak wajar, maupun karena **aturan deteksi** melihat _login_ gagal berulang atau pemindaian _port_.
- **Penahanan berlangsung dalam hitungan detik**, bukan jam.
- **Tidak ada pemulihan yang menghapus barang bukti.** Pemulihan dikunci sampai sidik jari bukti dicocokkan ulang.

| Indikator (terukur pada purwarupa) | Hasil |
| --- | --- |
| Peringatan dini: peluang serangan genset setelah kabar celah Modbus, sebelum dan sesudah Perketat (belum ada serangan) | **≈66% → ≈20%** |
| Waktu dari keputusan Operator sampai jalur pertama terputus, bukti sudah aman | **≈1,2 detik** |
| Deteksi _login_ gagal berulang dari satu alamat (ambang terbuka di kode, dikunci uji) | **8 kali dalam 60 detik** |
| Beban Central Processing Unit (CPU) _server_ untuk **300 layar** pemantau serentak, versi akhir | **≈1,5%** siaga · **≈1,7%** saat serangan |
| Lalu lintas jaringan ke 300 layar saat serangan intensif, berkat siaran ralat (uji beban 17 Okt 2026) | **−80%** (8,4 → 1,7 MB/s) |
| Waktu AI lokal menilai lalu lintas 9 aset (_Isolation Forest_, tanpa internet) | **≈10 milidetik** |
| Perilaku sistem yang dikunci uji otomatis | **411 uji** |

<p class="sumber-kecil">Angka CPU diukur ulang 26 Okt 2026 dengan tools/ukur_beban.py (Linux 2 inti, 300 siaran SSE sungguhan). Angka 2,8% pada versi dokumen sebelumnya diukur dengan alat dan mesin lain, sehingga tidak dibandingkan langsung. Asal setiap angka dan pemetaan ke lima kriteria penilaian ada di §7.</p>

> **Banyak sistem pertahanan berhenti di alarm.** Nusantara Shield berlanjut sampai bukti tersegel, jalur terputus, dan LAPSIT terbit, dalam satu alur yang dikunci _server_ setelah satu keputusan Operator, dan semuanya berjalan tanpa internet.

---

## 2. Latar Belakang, Urgensi, dan Pernyataan Masalah

### 2.1 Fakta Sejarah: Dua Kegagalan yang Sudah Terjadi

| Kejadian | Yang terjadi | Tahap Observe–Orient–Decide–Act (OODA) yang tertinggal |
| --- | --- | --- |
| **_Ransomware_ Brain Cipher di Pusat Data Nasional Sementara (PDNS) Surabaya, Juni 2024** | Menurut BSSN, upaya mematikan Windows Defender terekam **17 Juni 2024 pukul 23.15 WIB**, sedangkan aktivitas jahat baru berjalan **20 Juni pukul 00.54** dan Defender _crash_ semenit kemudian. Ada **≈49 jam** tanda bahaya yang tidak berbuah tindakan, dan hanya **≈2% data** punya cadangan. Layanan imigrasi lumpuh, layanan banyak instansi pusat dan daerah terganggu berhari-hari, dan pelaku meminta tebusan USD 8 juta. | **Amati dan Orientasi:** tanda bahaya ada, tetapi tidak dikenali dan tidak diputuskan tepat waktu |
| **Dugaan _ransomware_ LockBit 3.0 di Bank Syariah Indonesia (BSI), Mei 2023** | Layanan ATM dan _mobile banking_ terganggu **8–11 Mei**. Analis menduga penyusupan dimulai sejak **libur Lebaran**, dan pelaku mengklaim mencuri **1,5 TB data**. Saat layanan dipulihkan, hasil investigasi forensik resmi masih ditunggu. | **Amati** terlambat; **Bertindak** harus memilih antara memulihkan layanan secepatnya atau menjaga jejak forensik |

<div class="ilustrasi" id="ilustrasi-kliping">
<div style="display:flex;gap:10px">
<div style="flex:1">
<svg width="100%" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 540 250" role="img" aria-label="Ilustrasi insiden PDNS Juni 2024 menurut BSSN: upaya mematikan Windows Defender 17 Juni pukul 23.15, aktivitas jahat 20 Juni pukul 00.54, selang sekitar 49 jam; hanya sekitar 2 persen data punya cadangan">
<rect width="540" height="250" fill="#0d1729"/>
<text x="20" y="30" font-family="ui-monospace,Menlo,Consolas,monospace" font-size="13" font-weight="700" letter-spacing="1.5" fill="#ff5c74">PDNS SURABAYA · JUNI 2024</text>
<rect x="398" y="15" width="122" height="22" rx="5" fill="rgba(255,92,116,.15)" stroke="#ff5c74"/>
<text x="459" y="30" font-family="ui-monospace,Menlo,Consolas,monospace" font-size="11" fill="#ff5c74" text-anchor="middle" letter-spacing="1">RANSOMWARE</text>
<g>
<rect x="24" y="52" width="122" height="150" rx="8" fill="#101a2d" stroke="#2a3a58"/>
<g fill="#14213a" stroke="#22314d"><rect x="34" y="62" width="102" height="26" rx="3"/><rect x="34" y="96" width="102" height="26" rx="3"/><rect x="34" y="130" width="102" height="26" rx="3"/><rect x="34" y="164" width="102" height="26" rx="3"/></g>
<g fill="#ff5c74"><circle cx="45" cy="75" r="3"/><circle cx="45" cy="109" r="3"/><circle cx="45" cy="143" r="3"/><circle cx="45" cy="177" r="3"/></g>
<circle cx="85" cy="127" r="27" fill="#0b1324" stroke="#ff5c74" stroke-width="2.5"/>
<rect x="73" y="125" width="24" height="18" rx="3" fill="#ff5c74"/>
<path d="M78 125v-6a7 7 0 0 1 14 0v6" fill="none" stroke="#ff5c74" stroke-width="3"/>
<text x="85" y="226" font-size="12.5" fill="#d7e3f2" text-anchor="middle">Layanan imigrasi lumpuh</text>
</g>
<line x1="190" y1="78" x2="512" y2="78" stroke="#2a3a58" stroke-width="2"/>
<line x1="205" y1="78" x2="480" y2="78" stroke="#ff5c74" stroke-width="2" stroke-dasharray="4 4" opacity=".6"/>
<g font-size="11.5" fill="#8798b1">
<circle cx="205" cy="78" r="7" fill="#0d1729" stroke="#f2c14e" stroke-width="2.5"/>
<text x="205" y="106" text-anchor="middle" font-family="ui-monospace,Menlo,Consolas,monospace" font-weight="700" fill="#f2c14e">17 JUN 23.15</text>
<text x="205" y="122" text-anchor="middle">upaya matikan</text><text x="205" y="136" text-anchor="middle">Windows Defender</text>
<circle cx="345" cy="78" r="7" fill="#0d1729" stroke="#f2c14e" stroke-width="2.5"/>
<text x="345" y="106" text-anchor="middle" font-family="ui-monospace,Menlo,Consolas,monospace" font-weight="700" fill="#f2c14e">≈49 JAM</text>
<text x="345" y="122" text-anchor="middle">tanda bahaya,</text><text x="345" y="136" text-anchor="middle">tanpa tindakan</text>
<circle cx="480" cy="78" r="9" fill="#ff5c74"/>
<text x="480" y="106" text-anchor="middle" font-family="ui-monospace,Menlo,Consolas,monospace" font-weight="700" fill="#ff5c74">20 JUN 00.54</text>
<text x="480" y="122" text-anchor="middle">aktivitas jahat;</text><text x="480" y="136" text-anchor="middle">Defender crash</text>
</g>
<text x="190" y="176" font-size="12.5" fill="#d7e3f2">Data yang punya cadangan</text>
<text x="512" y="178" font-family="ui-monospace,Menlo,Consolas,monospace" font-size="22" font-weight="800" fill="#ff5c74" text-anchor="end">≈2%</text>
<rect x="190" y="188" width="322" height="14" rx="4" fill="#1f2d47"/>
<rect x="190" y="188" width="8" height="14" rx="4" fill="#ff5c74"/>
<text x="190" y="226" font-size="11.5" fill="#5b6c87">Tebusan USD 8 juta · layanan banyak instansi terganggu</text>
</svg>
</div>
<div style="flex:1">
<svg width="100%" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 540 250" role="img" aria-label="Ilustrasi insiden BSI Mei 2023: ATM dan mobile banking terganggu 8 sampai 11 Mei, pelaku mengklaim mencuri 1,5 TB data">
<rect width="540" height="250" fill="#0d1729"/>
<text x="20" y="30" font-family="ui-monospace,Menlo,Consolas,monospace" font-size="13" font-weight="700" letter-spacing="1.5" fill="#ff5c74">BANK SYARIAH INDONESIA · MEI 2023</text>
<rect x="356" y="15" width="164" height="22" rx="5" fill="rgba(255,92,116,.15)" stroke="#ff5c74"/>
<text x="438" y="30" font-family="ui-monospace,Menlo,Consolas,monospace" font-size="11" fill="#ff5c74" text-anchor="middle" letter-spacing="1">DUGAAN RANSOMWARE</text>
<g>
<rect x="26" y="58" width="78" height="104" rx="8" fill="#101a2d" stroke="#2a3a58"/>
<rect x="36" y="68" width="58" height="38" rx="3" fill="#14213a" stroke="#22314d"/>
<g fill="#22314d"><rect x="38" y="114" width="12" height="9" rx="2"/><rect x="54" y="114" width="12" height="9" rx="2"/><rect x="70" y="114" width="12" height="9" rx="2"/><rect x="38" y="127" width="12" height="9" rx="2"/><rect x="54" y="127" width="12" height="9" rx="2"/><rect x="70" y="127" width="12" height="9" rx="2"/></g>
<rect x="42" y="145" width="46" height="5" rx="2" fill="#0b1324"/>
<rect x="118" y="72" width="40" height="76" rx="7" fill="#101a2d" stroke="#2a3a58"/>
<rect x="123" y="80" width="30" height="56" rx="3" fill="#14213a"/>
<g stroke="#ff5c74" stroke-width="3" stroke-linecap="round"><path d="M57 79l16 16M73 79l-16 16M131 100l14 14M145 100l-14 14"/></g>
<text x="92" y="186" font-size="12.5" fill="#d7e3f2" text-anchor="middle">ATM dan <tspan font-style="italic">mobile banking</tspan></text>
<text x="92" y="202" font-size="12.5" fill="#d7e3f2" text-anchor="middle">terganggu</text>
</g>
<g font-family="ui-monospace,Menlo,Consolas,monospace" text-anchor="middle">
<rect x="196" y="56" width="72" height="80" rx="8" fill="rgba(255,92,116,.14)" stroke="#ff5c74"/>
<text x="232" y="90" font-size="26" font-weight="800" fill="#ff5c74">8</text><text x="232" y="106" font-size="10" fill="#8798b1">MEI</text><text x="232" y="125" font-size="10" fill="#ff5c74">GANGGUAN</text>
<rect x="276" y="56" width="72" height="80" rx="8" fill="rgba(242,193,78,.12)" stroke="#f2c14e"/>
<text x="312" y="90" font-size="26" font-weight="800" fill="#f2c14e">9</text><text x="312" y="106" font-size="10" fill="#8798b1">MEI</text><text x="312" y="125" font-size="10" fill="#f2c14e">BERANGSUR</text>
<rect x="356" y="56" width="72" height="80" rx="8" fill="rgba(242,193,78,.12)" stroke="#f2c14e"/>
<text x="392" y="90" font-size="26" font-weight="800" fill="#f2c14e">10</text><text x="392" y="106" font-size="10" fill="#8798b1">MEI</text><text x="392" y="125" font-size="10" fill="#f2c14e">BERANGSUR</text>
<rect x="436" y="56" width="76" height="80" rx="8" fill="rgba(62,240,161,.12)" stroke="#3ef0a1"/>
<text x="474" y="90" font-size="26" font-weight="800" fill="#3ef0a1">11</text><text x="474" y="106" font-size="10" fill="#8798b1">MEI</text><text x="474" y="125" font-size="10" fill="#3ef0a1">PULIH</text>
</g>
<text x="196" y="174" font-family="ui-monospace,Menlo,Consolas,monospace" font-size="22" font-weight="800" fill="#ff5c74">1,5 TB</text>
<text x="290" y="166" font-size="12.5" fill="#d7e3f2">data nasabah diklaim dicuri pelaku</text>
<text x="290" y="181" font-size="11" fill="#5b6c87">(klaim pelaku, belum terverifikasi)</text>
<text x="196" y="226" font-size="11.5" fill="#5b6c87">Penyusupan diduga sejak libur Lebaran (dugaan analis)</text>
</svg>
</div>
</div>
<p class="keterangan"><em>Ilustrasi dua insiden, diolah dari detikINET dan CNBC Indonesia (PDNS) serta Bisnis.com/CISSReC (BSI). Klaim pencurian 1,5 TB adalah klaim pelaku dan belum terverifikasi.</em></p>
</div>

**Akar masalahnya sama:** siklus OODA yang lambat dan tidak adanya prosedur berdoktrin yang dijalankan mesin. Penyusup sempat berdiam berhari-hari. Ketika layanan vital lumpuh, keputusan dan pemulihan dikejar waktu, sementara rantai barang bukti belum diamankan.

### 2.2 Proyeksi Ancaman: Fasilitas Kesehatan Satuan

> **Bayangkan jika kelumpuhan seperti PDNS terjadi pada infrastruktur kesehatan satuan, seperti RSPAD Gatot Soebroto atau rumah sakit jajaran Kesdam.** Serangan siber mendadak tidak hanya mengunci **rekam medis dan layanan klinis (IT)**, tetapi berpotensi mengambil alih **sistem kendali fasilitas (OT)** seperti genset dan kelistrikan ruang operasi. Di fasilitas kesehatan, lambat merespons insiden bukan sekadar soal data hilang, tetapi soal **nyawa dan keamanan nasional**.

Proyeksi ini berpijak pada dua kejadian nyata:

- **Data kesehatan Indonesia bernilai tinggi bagi penyerang.** Pada Mei 2021, **279 juta data** penduduk dijual di forum peretas. Sampel yang diperiksa Kominfo diduga kuat berasal dari BPJS Kesehatan.
- **_Ransomware_ sudah menyasar Operational Technology (OT) rumah sakit.** Pada **Agustus 2026**, Health Sciences Centre di Winnipeg, Kanada, melaporkan _ransomware_ yang mengenai sistem pemeliharaan fasilitas, termasuk **pendingin udara (HVAC) dan kendali akses pintu**. Pelayanan pasien tetap berjalan, karena jaringan klinis dan jaringan fasilitas terpisah.

Rumah sakit adalah arena tempat konvergensi Information Technology (IT) dan OT paling nyata. Pelajarannya: zona IT dan OT harus terpisah, ancaman OT harus dikenali lebih awal, dan jalur penyerang harus diputus dalam hitungan detik, tanpa menghapus bukti.

### 2.3 Jawaban Nusantara Shield

- **Deteksi dari peristiwa mentah.** Aturan deteksi di _server_ menghitung peristiwa _login_ dan koneksi masuk: **8 _login_ gagal dari satu alamat dalam 60 detik**, _login_ berhasil sesudah rentetan itu, atau **15 kombinasi aset:_port_ berbeda dalam 10 detik** (pemindaian _port_). Ambangnya tertulis terbuka di kode dan dikunci uji. Hasilnya hanya menaikkan aset ke WASPADA.
- **Amati lebih awal, IT maupun OT.** Kabar ancaman dikorelasikan dengan inventaris aset. Kabar celah protokol industri Modbus langsung menaikkan **pengendali genset** ke WASPADA (≈66%) sebelum ada serangan, dan satu klik **Perketat** menurunkannya. **AI lokal** (_Isolation Forest_) juga menilai lalu lintas tiap aset; lalu lintas Modbus tak wajar menaikkan genset ke WASPADA **tanpa menunggu kabar ancaman**, lengkap dengan alasannya.
- **Bukti dulu, baru putus: IT dan OT.** Bukti disegel dengan sidik jari Secure Hash Algorithm 256-bit (SHA-256), lalu **≈1,2 detik** kemudian aset IT diisolasi. Untuk OT, perintah ke sakelar terkelola memutus **jalur kantor → zona kendali**, sehingga peretasan tidak menjalar ke infrastruktur fisik. Genset **tidak dimatikan**, tetapi beralih ke kendali lokal (NIST SP 800-82). Pemutusan tanpa bukti ditolak _server_.
- **Pemulihan tidak menghapus jejak.** Tombol Pulihkan terkunci sampai sidik jari SHA-256 bukti **dicocokkan ulang**.
- **Tidak menggantungkan pertahanan pada pusat data di luar kendali satuan.** Saat PDNS lumpuh, layanan banyak instansi yang dititipkan di sana ikut berhenti, dan hanya sekitar 2% data yang punya cadangan. Pelajarannya: inti pertahanan satuan (deteksi, keputusan isolasi, bukti, dan laporan) harus tetap berjalan di _server_ posko sendiri, tanpa awan dan tanpa internet (lihat 5.1).
- **Batas yang jujur:** di purwarupa, rumah sakit dan genset adalah data contoh, dan perintah ke sakelar masih berupa **simulasi webhook**. Sensor protokol industri dan sambungan ke sakelar fisik adalah peta jalan.

<p class="sumber-kecil">Sumber: <a href="https://inet.detik.com/security/d-7407568/kronologi-serangan-ransomware-bikin-pusat-data-kolaps-berhari-hari/amp">detikINET (PDNS)</a> · <a href="https://inet.detik.com/security/d-7409026/bssn-windows-defender-pusat-data-i-crash-i-sebelum-ransomware-beraksi">detikINET, kronologi BSSN (26 Juni 2024)</a> · <a href="https://kalsel.antaranews.com/berita/419220/menkominfo-jelaskan-kronologi-serangan-siber-pdns-2">ANTARA, Raker Komisi I DPR (27 Juni 2024)</a> · <a href="https://www.cnbcindonesia.com/tech/20240628080944-37-550082/alasan-backup-pusat-data-nasional-hanya-2-akhirnya-terungkap">CNBC Indonesia (cadangan 2%)</a> · <a href="https://teknologi.bisnis.com/read/20230514/84/1655787/cissrec-tim-it-bsi-cepat-dan-responsif">Bisnis (pemulihan BSI)</a> · <a href="https://finansial.bisnis.com/read/20230514/90/1655733/kronologi-bsi-diserang-ransomware-oleh-hacker-lockbit-30-diduga-beraksi-sejak-libur-lebaran-2023">Bisnis (kronologi BSI)</a> · <a href="https://www.cnnindonesia.com/teknologi/20210521115652-185-645201/kominfo-telusuri-279-juta-data-bocor-diduga-kuat-dari-bpjs">CNN Indonesia (279 juta data)</a> · <a href="https://www.nozominetworks.com/blog/when-ransomware-turns-off-the-hvac-lessons-from-the-winnipeg-hospital-incident">Nozomi Networks (Winnipeg HSC)</a></p>

### 2.4 Empat Kelemahan Pola Respons Manual

Empat kelemahan berikut lazim ditemui pada pola respons insiden manual:

| # | Masalah | Gejala di lapangan | Akibat bagi satuan |
| --- | --- | --- | --- |
| **1** | **Banjir peringatan** (*alert fatigue*) | Ratusan peringatan per hari, sebagian besar tidak menyangkut aset satuan | Ancaman nyata tenggelam; Operator lelah dan terlambat bereaksi |
| **2** | **Penahanan (*containment*) yang lambat dan ragu** | Izin berjenjang, tombol bermakna ganda, laporan disusun manual di tengah krisis | Penyerang leluasa menyebar selama keputusan tertunda |
| **3** | **Rusaknya bukti forensik saat pemulihan darurat** | _Server_ di-*restart* atau dipulihkan dari cadangan sebelum bukti disalin | Pelaku tidak bisa diidentifikasi; rantai barang bukti (*chain of custody*) tidak dapat dipertanggungjawabkan |
| **4** | **Petugas jaga bukan ahli siber, dan jarang berlatih** | Ahli siber di satuan hanya satu atau dua orang; latihan tanggap insiden jarang, mahal, dan tidak dinilai | Saat insiden datang, urutan tindakan dipelajari di tengah krisis |

Kelemahan keempat muncul dari dua sumber. Diskusi komunitas peserta (November 2026), yang merujuk visi-misi Satuan Siber (Satsiber) TNI dan layanan Tim Tanggap Insiden Siber (TTIS) TNI AD, menyebut masalah terbesar di lingkungan TNI: *ransomware* dan *phishing*, sistem lama yang sulit diperbarui, dan **kurangnya SDM siber spesialis**. Misi Satsiber TNI sendiri memuat pembentukan prajurit siber dan sosialisasi keamanan informasi kepada personel. Webinar pembekalan Kartika Cyber Hackathon 2026 menyebut hal yang sama dan menunjuk latihan (*cyber drill*) sebagai cara membangun kesiapan yang terukur.

> **Inti persoalannya:** kecepatan dan ketertiban forensik selama ini dianggap saling bertentangan. Nusantara Shield membuktikan keduanya bisa dicapai sekaligus.

---

## 3. Solusi yang Ditawarkan

### 3.1 Cara Kerja dalam Siklus OODA

<div class="ilustrasi" id="ilustrasi-radar" style="max-width:72%;margin-left:auto;margin-right:auto">
<svg viewBox="0 0 500 300" width="100%" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Ilustrasi Radar Anomali: jarak dari pusat menunjukkan zona jaringan, warna menunjukkan tingkat keparahan" style="font-family:ui-monospace,Menlo,Consolas,'DejaVu Sans Mono',monospace">
  <defs>
    <radialGradient id="rdBg" cx="50%" cy="50%" r="50%"><stop offset="0" stop-color="#13284a"/><stop offset="1" stop-color="#0b1a33"/></radialGradient>
    <linearGradient id="rdSapu" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#10b981" stop-opacity="0"/><stop offset="1" stop-color="#10b981" stop-opacity=".38"/></linearGradient>
    <pattern id="rdGrid" width="20" height="20" patternUnits="userSpaceOnUse"><path d="M20 0H0V20" fill="none" stroke="#64748b" stroke-opacity=".14" stroke-width="1"/></pattern>
  </defs>
  <rect width="500" height="300" rx="10" fill="#0b1a33"/>
  <rect width="500" height="300" rx="10" fill="url(#rdGrid)"/>
  <!-- zona: luar gerbang / DMZ / internal -->
  <circle cx="150" cy="150" r="126" fill="url(#rdBg)" stroke="#94a3b8" stroke-opacity=".7"/>
  <circle cx="150" cy="150" r="126" fill="#dc2626" fill-opacity=".05"/>
  <circle cx="150" cy="150" r="84" fill="#f59e0b" fill-opacity=".05" stroke="#94a3b8" stroke-opacity=".55"/>
  <circle cx="150" cy="150" r="42" fill="#10b981" fill-opacity=".07" stroke="#94a3b8" stroke-opacity=".55"/>
  <line x1="276.0" y1="150.0" x2="269.0" y2="150.0" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="274.1" y1="171.9" x2="270.6" y2="171.3" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="268.4" y1="193.1" x2="265.1" y2="191.9" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="259.1" y1="213.0" x2="253.1" y2="209.5" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="246.5" y1="231.0" x2="243.8" y2="228.7" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="231.0" y1="246.5" x2="228.7" y2="243.8" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="213.0" y1="259.1" x2="209.5" y2="253.1" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="193.1" y1="268.4" x2="191.9" y2="265.1" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="171.9" y1="274.1" x2="171.3" y2="270.6" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="150.0" y1="276.0" x2="150.0" y2="269.0" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="128.1" y1="274.1" x2="128.7" y2="270.6" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="106.9" y1="268.4" x2="108.1" y2="265.1" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="87.0" y1="259.1" x2="90.5" y2="253.1" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="69.0" y1="246.5" x2="71.3" y2="243.8" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="53.5" y1="231.0" x2="56.2" y2="228.7" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="40.9" y1="213.0" x2="46.9" y2="209.5" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="31.6" y1="193.1" x2="34.9" y2="191.9" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="25.9" y1="171.9" x2="29.4" y2="171.3" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="24.0" y1="150.0" x2="31.0" y2="150.0" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="25.9" y1="128.1" x2="29.4" y2="128.7" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="31.6" y1="106.9" x2="34.9" y2="108.1" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="40.9" y1="87.0" x2="46.9" y2="90.5" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="53.5" y1="69.0" x2="56.2" y2="71.3" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="69.0" y1="53.5" x2="71.3" y2="56.2" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="87.0" y1="40.9" x2="90.5" y2="46.9" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="106.9" y1="31.6" x2="108.1" y2="34.9" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="128.1" y1="25.9" x2="128.7" y2="29.4" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="150.0" y1="24.0" x2="150.0" y2="31.0" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="171.9" y1="25.9" x2="171.3" y2="29.4" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="193.1" y1="31.6" x2="191.9" y2="34.9" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="213.0" y1="40.9" x2="209.5" y2="46.9" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="231.0" y1="53.5" x2="228.7" y2="56.2" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="246.5" y1="69.0" x2="243.8" y2="71.3" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="259.1" y1="87.0" x2="253.1" y2="90.5" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="268.4" y1="106.9" x2="265.1" y2="108.1" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/><line x1="274.1" y1="128.1" x2="270.6" y2="128.7" stroke="#94a3b8" stroke-opacity=".55" stroke-width="1"/>
  <!-- garis bidik (crosshair) -->
  <g stroke="#94a3b8" stroke-opacity=".35" stroke-width="1"><line x1="16" y1="150" x2="284" y2="150"/><line x1="150" y1="16" x2="150" y2="284"/></g>
  <g stroke="#10b981" stroke-width="1.6" fill="none"><path d="M136 150h-8M164 150h8M150 136v-8M150 164v8"/><circle cx="150" cy="150" r="6"/></g>
  <!-- sapuan senter -->
  <path d="M150 150L182.6 28.3A126 126 0 0 1 253.2 77.7Z" fill="url(#rdSapu)"/>
  <line x1="150" y1="150" x2="253.2" y2="77.7" stroke="#10b981" stroke-width="1.8"/>
  <circle cx="130.9" cy="139.0" r="3" fill="#10b981"/><circle cx="165.0" cy="124.0" r="3" fill="#10b981"/><circle cx="176.0" cy="171.9" r="3" fill="#10b981"/><circle cx="133.3" cy="169.9" r="3" fill="#10b981"/><circle cx="128.8" cy="91.7" r="9" fill="none" stroke="#f59e0b" stroke-width="1" stroke-dasharray="3 2.5"/><circle cx="128.8" cy="91.7" r="4.2" fill="#f59e0b"/><circle cx="217.6" cy="168.1" r="9" fill="none" stroke="#f59e0b" stroke-width="1" stroke-dasharray="3 2.5"/><circle cx="217.6" cy="168.1" r="4.2" fill="#f59e0b"/><circle cx="229.7" cy="83.2" r="11" fill="none" stroke="#dc2626" stroke-opacity=".45" stroke-width="1"/><circle cx="229.7" cy="83.2" r="4.2" fill="#dc2626"/><circle cx="140.2" cy="261.6" r="11" fill="none" stroke="#dc2626" stroke-opacity=".45" stroke-width="1"/><circle cx="140.2" cy="261.6" r="4.2" fill="#dc2626"/><circle cx="53.4" cy="175.9" r="11" fill="none" stroke="#dc2626" stroke-opacity=".45" stroke-width="1"/><circle cx="53.4" cy="175.9" r="4.2" fill="#dc2626"/><rect x="205.0" y="248.2" width="8" height="8" fill="#60a5fa"/>
  <!-- label zona -->
  <g font-size="8.5" fill="#94a3b8" letter-spacing=".8">
    <text x="154" y="119">INTERNAL</text>
    <text x="154" y="77">DMZ</text>
    <text x="154" y="35">LUAR GERBANG</text>
  </g>
  <!-- panel HUD Puskodal -->
  <rect x="300" y="18" width="182" height="264" rx="8" fill="#13284a" stroke="#64748b" stroke-opacity=".6"/>
  <text x="314" y="40" font-size="10" fill="#10b981" font-weight="700" letter-spacing="1.2">PUSKODAL · RADAR</text>
  <text x="314" y="54" font-size="8" fill="#94a3b8">ANOMALI JARINGAN · LANGSUNG</text>
  <line x1="314" y1="62" x2="468" y2="62" stroke="#64748b" stroke-opacity=".6"/>
  <text x="314" y="80" font-size="8" fill="#94a3b8">POSTUR</text>
  <text x="468" y="80" font-size="10" fill="#dc2626" font-weight="700" text-anchor="end">KRITIS</text>
  <text x="314" y="98" font-size="8" fill="#94a3b8">PUTARAN</text>
  <text x="468" y="98" font-size="9" fill="#e2e8f0" text-anchor="end">2,2 dtk</text>
  <line x1="314" y1="108" x2="468" y2="108" stroke="#64748b" stroke-opacity=".6"/>
  <text x="314" y="124" font-size="8" fill="#94a3b8" letter-spacing=".6">JARAK DARI PUSAT = ZONA</text>
  <text x="314" y="137" font-size="8" fill="#e2e8f0">dalam · tengah · luar</text>
  <text x="314" y="157" font-size="8" fill="#94a3b8" letter-spacing=".6">WARNA = KEPARAHAN</text>
  <circle cx="318" cy="172" r="3.5" fill="#10b981"/><text x="327" y="175" font-size="8.5" fill="#e2e8f0">Normal</text><text x="468" y="175" font-size="8.5" fill="#e2e8f0" text-anchor="end">4</text>
  <circle cx="318" cy="189" r="3.5" fill="#f59e0b"/><text x="327" y="192" font-size="8.5" fill="#e2e8f0">Berisiko (prediksi CTI)</text><text x="468" y="192" font-size="8.5" fill="#e2e8f0" text-anchor="end">2</text>
  <circle cx="318" cy="206" r="3.5" fill="#dc2626"/><text x="327" y="209" font-size="8.5" fill="#e2e8f0">Ancaman</text><text x="468" y="209" font-size="8.5" fill="#dc2626" font-weight="700" text-anchor="end">3</text>
  <rect x="314.5" y="219.5" width="7" height="7" fill="#60a5fa"/><text x="327" y="226" font-size="8.5" fill="#e2e8f0">Diblokir</text><text x="468" y="226" font-size="8.5" fill="#e2e8f0" text-anchor="end">1</text>
  <line x1="314" y1="238" x2="468" y2="238" stroke="#64748b" stroke-opacity=".6"/>
  <text x="314" y="254" font-size="7.5" fill="#94a3b8">Arah titik = penanda alamat IP,</text>
  <text x="314" y="266" font-size="7.5" fill="#94a3b8">bukan lokasi geografis.</text>
</svg>
</div>

*Ilustrasi konsep **Radar Anomali** pada tahap Amati: jarak dari pusat menunjukkan zona jaringan, warna menunjukkan tingkat keparahan.*


| Tahap OODA | Pertanyaan komandan | Jawaban Nusantara Shield (sudah berjalan) |
| --- | --- | --- |
| **Amati** (*Observe*) | Apa yang terjadi di jaringan? | Aset **IT dan OT**, **Radio Cyber Threat Intelligence (CTI)/OSINT**, Radar Anomali, dan Peta Ancaman Global dalam satu layar |
| **Orientasi** (*Orient*) | Apakah ini menyangkut aset kita? | **Korelasi otomatis** antara kabar ancaman dan inventaris aset, ditambah **skor anomali AI lokal** atas lalu lintas tiap aset, menghasilkan **peluang serangan per aset** (_risk-based scoring_): 1 − (1 − p<sub>CTI</sub>)(1 − p<sub>AI</sub>). Peluang ≥50% menaikkan aset ke **WASPADA** sebelum diserang. |
| **Putuskan** (*Decide*) | Tindakan apa yang diizinkan? | _Playbook_ **praotorisasi** (*pre-authorized*). Operator cukup **menahan tombol 0,6 detik**, sehingga tidak ada klik panik. |
| **Bertindak** (*Act*) | Bagaimana mengeksekusi tanpa merusak bukti? | Urutan terkunci di _server_: **amankan bukti (SHA-256) → isolasi → Laporan Situasi (LAPSIT) otomatis → pemulihan setelah _hash_ dicocokkan ulang** |

Dalam bahasa _incident response_ militer, tahap Bertindak setara dengan siklus **_detect_ → _contain_ → _eradicate_ → _recover_**, ditutup **_After-Action Review_ (AAR)**. Nusantara Shield menegakkan tiga prinsipnya: kontainmen tanpa mematikan fungsi layanan (_mission continuity_), pembersihan tanpa menghapus jejak forensik, dan pemulihan hanya setelah bukti terverifikasi (Purbo dan Lumy, 2025).

### 3.2 Empat Pilar Kemampuan

1. **Penangkalan dini (lapis pertama)**
    - Kabar ancaman dikorelasikan dengan _port_ dan sektor aset milik satuan, **termasuk aset OT**: kabar celah protokol industri Modbus langsung menaikkan pengendali genset ke WASPADA.
    - **AI lokal — Mesin Deteksi Anomali (_anomaly detection engine_):** model _Isolation Forest_ (scikit-learn) dilatih di _server_ satuan dari profil lalu lintas normal, lalu menilai enam ciri lalu lintas tiap aset dalam milidetik. Lalu lintas tidak wajar menambah peluang serangan dan disertai alasan yang bisa dibaca, misalnya "perintah tulis Modbus 10× normal" (_explainability_).
    - **Mesin Deteksi Aturan (_rule-based detection engine_):** menghitung peristiwa mentah (_login_ dan koneksi masuk) dengan ambang terbuka: _login_ gagal berulang (8 dalam 60 detik), _login_ tembus sesudah rentetan gagal (≤ 120 detik), dan pemindaian _port_ (15 kombinasi aset:_port_ dalam 10 detik). Peringatannya ikut aturan yang sama dengan CTI dan AI: hanya menaikkan WASPADA, dapat diperketat, dan dapat ditutup lewat triase.
    - Satu klik **Perketat** menurunkan peluang serangan sebelum ancaman tiba.
2. **Respons berdoktrin (lapis kedua, bila ancaman tetap tembus)**
    - **Isolasi standar:** bukti diamankan lebih dulu, lalu ≈1,2 detik kemudian jaringan diputus.
    - **Isolasi Darurat (*Emergency Override*):** bila alat forensik gagal, Operator tetap bisa memutus jaringan, tetapi **wajib menulis alasan** (minimal 15 karakter) dan menahan tombol **1,5 detik**.
    - Setiap jalan pintas ditolak _server_ (kode **409**).
3. **Akuntabilitas tak terbantahkan**
    - **Buku Rantai Bukti:** sidik jari SHA-256 tiap barang bukti, petugas, waktu, dan lokasi simpan.
    - **Log audit HMAC berantai:** satu catatan diubah, rantai langsung putus dan ketahuan.
    - **LAPSIT otomatis** bernomor (IR-2026-001…) terbit **hanya setelah semua tindakan pemutusan tuntas**, merujuk nomor bukti atau alasan darurat.
    - **Peringatan terbaru** menyebut nama Operator yang mengisolasi dan nomor berita acara bukti yang sebenarnya; KPI **Waktu respons (MTTC)** dan **Insiden sejak posko aktif** dihitung dari kejadian yang tercatat.
4. **Hemat sumber daya jaringan satuan**
    - Satu "dapur" memasak gambaran situasi sekali per detik untuk semua layar.
    - Layar hanya menerima **ralat (delta)**, bukan gambar utuh, sehingga lalu lintas turun hingga **80%**.
    - Cocok untuk jaringan satuan berpita sempit.

### 3.3 Terlatih Sebelum Insiden: Drill Kesiapan

Perpres 82/2022 memasukkan sektor **kesehatan** dan **pertahanan** sebagai Infrastruktur Informasi Vital (Pasal 4) dan mewajibkan simulasi tanggap Insiden Siber (Pasal 15). **Drill Kesiapan** menjalankan simulasi itu di dasbor yang sama dengan yang dipakai saat insiden sungguhan:

1. Log sintetis satu cerita (akun layanan cadangan dibobol, lalu pencadangan dimatikan) dibaca **Mesin Deteksi Aturan yang sama** dengan log asli. Aturan yang seharusnya menangkap tetapi diam ikut dilaporkan.
2. Insiden latihan dimulai. Operator menanganinya dari Action Center dan menjawab **satu pertanyaan per fase** penanganan insiden (Deteksi, Analisis, Penahanan, Pemulihan).
3. *Server* menghitung **nilai 0–100 dari jejak yang tercatat**, bukan dari pengakuan: ketepatan keputusan 40, bukti sebelum putus 30, kecepatan penahanan (MTTC) 30. Rumusnya terbuka; hasilnya masuk log audit berantai dan LAPSIT sebagai **LATIHAN**.

Dengan begitu, Operator yang bukan ahli siber dilatih urutan tindakan yang benar sebelum insiden, lalu dipandu urutan yang sama saat insiden sungguhan. Rincian dan batasnya: Dokumentasi Teknis §3.5.

Untuk posko yang dijaga 24 jam, panel Beban Jaringan menampilkan **linimasa 60 menit** berlabel "data latihan" beserta **pita anomali AI per aset** (nama aset, lama, dan alasannya). Tampilannya mengikuti tiga lapis yang dianjurkan untuk pusat komando siber: **_strategic heatmap_** (Peta Global dan kotak Postur), **_operational incident board_** (Action Center dan LAPSIT), dan **_tactical endpoint list_** (Topologi Internal dan daftar aset), dengan **_human-in-the-loop_** pada setiap keputusan pemutusan.

---

## 4. Keunggulan Taktis (Military Value Proposition)

Seluruh keunggulan berikut **sudah berjalan** di purwarupa dan dapat didemonstrasikan.

| Prinsip | Penerapan di Nusantara Shield |
| --- | --- |
| **_Human-in-the-loop_** — komandan memegang keputusan | Tidak ada tindakan pemutusan tanpa Operator menahan tombol. Pemulihan terkunci sampai syaratnya terpenuhi. Pengecualian darurat wajib beralasan tertulis. |
| **Sistem pendukung keputusan, bukan pengganti keputusan** | Sengaja **tidak** otonom penuh. Di jaringan vital, respons otomatis penuh membuka tiga risiko: peringatan keliru yang memutus layanan sendiri, respons yang dapat dipancing pihak luar, dan pemutusan tanpa pejabat yang bertanggung jawab. Kecepatan tetap terjaga: isolasi praotorisasi cukup ditahan 0,6 detik, dan pemutusan selesai ≈1,2 detik dengan bukti disegel lebih dulu. |
| **Mode Berdaulat** — tanpa ketergantungan pihak luar | Berjalan **luring penuh**: tanpa Content Delivery Network (CDN), fon, atau layanan awan. Cocok untuk **jaringan tertutup** satuan. Data latihan sintetis (RFC 5737). |
| **Doktrin forensik** — *chain of custody* | Bukti diamankan **sebelum** isolasi. Berita acara berantai HMAC. Sidik jari SHA-256 **dicocokkan ulang sebelum pemulihan**; bila tidak cocok, pemulihan dikunci. |
| **Kecepatan OODA** — bertindak lebih cepat dari lawan | Peringatan dini sebelum serangan; bukti + isolasi ≈1,2 detik dari keputusan |
| **AI tepat guna** — deteksi tanpa _signature_ | _Isolation Forest_ lokal menilai lalu lintas dalam milidetik, menjelaskan alasannya, dan hanya menaikkan status; keputusan memutus tetap di tangan Operator (_human-in-the-loop_). Dikunci 10 uji khusus AI. |
| **Pertanggungjawaban komando** | Setiap keputusan (siapa, apa, kapan, alasan) tercatat di dua buku HMAC. LAPSIT terkirim otomatis ke pimpinan. |
| **Pemisahan wewenang** | Peran **Pengamat** (melihat) dan **Operator** (bertindak). Akun Operator hanya lewat kode undangan atau dibuat Operator lain. |
| **Posko yang dijaga berlapis** | Alat yang memegang tombol isolasi harus paling terlindungi. Kata sandi disimpan dengan PBKDF2-SHA256 (200.000 putaran), sesi memakai token acak yang kedaluwarsa, _login_ dibatasi 5 percobaan per menit, kiriman dibatasi 16 KB, dan antarmuka dikunci kebijakan keamanan konten (_Content Security Policy_, CSP). Dikunci uji keamanan; rincian dan batasnya di Dokumentasi Teknis §2.7. |
| **Selaras NIST CSF 2.0** | Fitur dipetakan ke enam fungsi _Cybersecurity Framework_ (CSF) 2.0 (tabel di bawah). Pemetaan mandiri oleh tim, bukan sertifikasi. |
| **Sinergi IT/OT** | Aset rumah sakit (SIMRS) dan aset kendali (**pengendali genset**, Modbus/TCP _port_ 502) berada dalam satu inventaris dan satu layar. Kabar ancaman protokol industri langsung dikorelasikan, dan skenario **Sabotase OT** memutus jalur kantor → zona kendali ≈1,2 detik sejak keputusan Operator (bukti diamankan di awal jeda). Dikunci 6 uji khusus OT. |
| **Bahasa satuan** | Seluruh label (jabatan penerima laporan, nama satuan) diatur dari **satu kamus istilah**, tanpa mengubah logika |

**Pemetaan ke NIST _Cybersecurity Framework_ (CSF) 2.0.** Kerangka ini lazim dipakai untuk menilai kelengkapan program keamanan siber. Keenam fungsinya sudah diisi fitur yang berjalan; rincian per kategori beserta uji yang membuktikannya ada di Dokumentasi Teknis §2.6.

| Fungsi CSF 2.0 | Sudah berjalan di Nusantara Shield | Masih peta jalan |
| --- | --- | --- |
| **_Govern_** (tata kelola) | Dua peran dan dua kunci konfirmasi; Nilai Kesiapan Siber A–E untuk Dansat | — |
| **_Identify_** (kenali) | Inventaris aset IT dan OT; korelasi kabar ancaman × aset; peluang serangan per aset | Inventaris dari sistem satuan yang sebenarnya |
| **_Protect_** (lindungi) | Perketat (simulasi pengerasan); kepatuhan pencadangan < 24 jam dan uji pulih; akses posko berlapis | Pengerasan langsung di perangkat nyata |
| **_Detect_** (deteksi) | AI lokal (_Isolation Forest_); aturan deteksi _login_ gagal berulang dan pemindaian _port_, dan aturan OT (atas peristiwa sintetis maupun **log asli yang diimpor Operator**); radar anomali; triase peringatan | Sensor nyata; peristiwa identitas dari Active Directory (perubahan hak akses, akun baru) |
| **_Respond_** (tanggapi) | Bukti dulu → isolasi ≈1,2 detik → LAPSIT; isolasi darurat beralasan; MTTC tercatat | Pengiriman LAPSIT berjenjang otomatis ke Sansidam dan Kartika CSIRT; respons bertingkat menurut kritikalitas aset |
| **_Recover_** (pulihkan) | Pemulihan terkunci sampai sidik jari bukti cocok ulang | — |

<div class="ilustrasi" id="ilustrasi-ooda" style="max-width:62%;margin-left:auto;margin-right:auto">
<svg viewBox="0 0 720 400" width="100%" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Siklus OODA Nusantara Shield: Amati, Orientasi, Putuskan, Bertindak, berulang terus" style="font-family:Inter,'Segoe UI','DejaVu Sans',Arial,sans-serif">
  <defs>
    <radialGradient id="odBg" cx="50%" cy="45%" r="70%"><stop offset="0" stop-color="#13284a"/><stop offset="1" stop-color="#0b1a33"/></radialGradient>
    <pattern id="odGrid" width="24" height="24" patternUnits="userSpaceOnUse"><path d="M24 0H0V24" fill="none" stroke="#64748b" stroke-opacity=".12" stroke-width="1"/></pattern>
    <marker id="odPanah" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#f5c451"/></marker>
  </defs>
  <rect width="720" height="400" rx="12" fill="url(#odBg)"/>
  <rect width="720" height="400" rx="12" fill="url(#odGrid)"/>
  <text x="360" y="40" font-size="25" font-weight="800" fill="#f5c451" text-anchor="middle" letter-spacing="4">SIKLUS OODA</text>
  <text x="360" y="61" font-size="12" fill="#94a3b8" text-anchor="middle">Siklus keputusan berulang · mesin menyiapkan, manusia memutuskan</text>
  <circle cx="360" cy="232" r="134" fill="none" stroke="#64748b" stroke-opacity=".35" stroke-dasharray="2 6"/>
  <circle cx="360" cy="232" r="66" fill="#0b1a33" fill-opacity=".6" stroke="#64748b" stroke-opacity=".45"/>
  <text x="360" y="226" font-size="12" font-weight="700" fill="#cbd5e1" text-anchor="middle" letter-spacing="1.5">SIKLUS</text>
  <text x="360" y="241" font-size="12" font-weight="700" fill="#cbd5e1" text-anchor="middle" letter-spacing="1.5">BERULANG</text>
  <text x="360" y="259" font-size="9" fill="#10b981" text-anchor="middle" font-family="ui-monospace,Menlo,Consolas,'DejaVu Sans Mono',monospace">jejak HMAC</text>
  <path d="M402.3 121.8A118 118 0 0 1 470.2 189.7" fill="none" stroke="#f5c451" stroke-width="2.4" stroke-dasharray="7 5" marker-end="url(#odPanah)"/><path d="M470.2 274.3A118 118 0 0 1 402.3 342.2" fill="none" stroke="#f5c451" stroke-width="2.4" stroke-dasharray="7 5" marker-end="url(#odPanah)"/><path d="M317.7 342.2A118 118 0 0 1 249.8 274.3" fill="none" stroke="#f5c451" stroke-width="2.4" stroke-dasharray="7 5" marker-end="url(#odPanah)"/><path d="M249.8 189.7A118 118 0 0 1 317.7 121.8" fill="none" stroke="#f5c451" stroke-width="2.4" stroke-dasharray="7 5" marker-end="url(#odPanah)"/>
  <circle cx="360.0" cy="114.0" r="42" fill="none" stroke="#10b981" stroke-opacity=".28" stroke-width="5"/><circle cx="360.0" cy="114.0" r="36" fill="#0b1a33" stroke="#10b981" stroke-width="2.4"/><circle cx="360.0" cy="114.0" r="15" fill="none" stroke="#10b981" stroke-width="1.6"/><circle cx="360.0" cy="114.0" r="8" fill="none" stroke="#10b981" stroke-width="1.2" stroke-opacity=".7"/><path d="M342.0 114.0H378.0M360.0 96.0V132.0" stroke="#10b981" stroke-width="1" stroke-opacity=".55"/><path d="M360.0 114.0L371.0 104.0" stroke="#10b981" stroke-width="2" stroke-linecap="round"/><circle cx="366.0" cy="121.0" r="2.6" fill="#dc2626"/><circle cx="478.0" cy="232.0" r="42" fill="none" stroke="#60a5fa" stroke-opacity=".28" stroke-width="5"/><circle cx="478.0" cy="232.0" r="36" fill="#0b1a33" stroke="#60a5fa" stroke-width="2.4"/><line x1="467.0" y1="224.0" x2="489.0" y2="224.0" stroke="#60a5fa" stroke-width="1.6"/><line x1="489.0" y1="224.0" x2="478.0" y2="243.0" stroke="#60a5fa" stroke-width="1.6"/><line x1="478.0" y1="243.0" x2="467.0" y2="224.0" stroke="#60a5fa" stroke-width="1.6"/><circle cx="467.0" cy="224.0" r="4.5" fill="#13284a" stroke="#60a5fa" stroke-width="1.8"/><circle cx="489.0" cy="224.0" r="4.5" fill="#13284a" stroke="#60a5fa" stroke-width="1.8"/><circle cx="478.0" cy="243.0" r="4.5" fill="#13284a" stroke="#60a5fa" stroke-width="1.8"/><circle cx="478.0" cy="230.0" r="2.4" fill="#f59e0b"/><circle cx="360.0" cy="350.0" r="42" fill="none" stroke="#f5c451" stroke-opacity=".28" stroke-width="5"/><circle cx="360.0" cy="350.0" r="36" fill="#0b1a33" stroke="#f5c451" stroke-width="2.4"/><circle cx="360.0" cy="350.0" r="14" fill="none" stroke="#f5c451" stroke-opacity=".3" stroke-width="3"/><path d="M360.0 336.0A14 14 0 1 1 346.0 350.0" fill="none" stroke="#f5c451" stroke-width="3" stroke-linecap="round"/><text x="360.0" y="354.0" font-size="10" font-weight="700" fill="#f5c451" text-anchor="middle" font-family="ui-monospace,Menlo,Consolas,'DejaVu Sans Mono',monospace">0,6</text><circle cx="242.0" cy="232.0" r="42" fill="none" stroke="#dc2626" stroke-opacity=".28" stroke-width="5"/><circle cx="242.0" cy="232.0" r="36" fill="#0b1a33" stroke="#dc2626" stroke-width="2.4"/><path d="M242.0 215.0L255.0 221.0V232.0C255.0 241.0 249.0 246.0 242.0 249.0C235.0 246.0 229.0 241.0 229.0 232.0V221.0Z" fill="none" stroke="#dc2626" stroke-width="1.8"/><rect x="236.0" y="230.0" width="12" height="9" rx="1.5" fill="#dc2626"/><path d="M238.5 230.0V227.0A3.5 3.5 0 0 1 245.5 227.0V230.0" fill="none" stroke="#dc2626" stroke-width="1.6"/>
  <path d="M398 114.0H522M398 350.0H522" stroke="#64748b" stroke-opacity=".6" stroke-dasharray="2 3"/>
  <text x="530" y="100" font-size="15" fill="#10b981" text-anchor="start" font-weight="700">01 · AMATI</text>
  <text x="530" y="120" font-size="11.5" fill="#cbd5e1" text-anchor="start">Sensor jaringan, radio CTI/</text>
  <text x="530" y="135" font-size="11.5" fill="#cbd5e1" text-anchor="start">OSINT, dan radar anomali</text>
  <text x="530" y="150" font-size="11.5" fill="#cbd5e1" text-anchor="start">dalam satu layar.</text>
  <text x="530" y="214" font-size="15" fill="#60a5fa" text-anchor="start" font-weight="700">02 · ORIENTASI</text>
  <text x="530" y="234" font-size="11.5" fill="#cbd5e1" text-anchor="start">Korelasi ancaman × aset satuan:</text>
  <text x="530" y="249" font-size="11.5" fill="#cbd5e1" text-anchor="start">peluang serangan per aset.</text>
  <text x="530" y="264" font-size="11.5" fill="#cbd5e1" text-anchor="start">≥50% → aset naik WASPADA.</text>
  <text x="530" y="336" font-size="15" fill="#f5c451" text-anchor="start" font-weight="700">03 · PUTUSKAN</text>
  <text x="530" y="356" font-size="11.5" fill="#cbd5e1" text-anchor="start"><tspan font-style="italic">Playbook</tspan> praotorisasi. Operator</text>
  <text x="530" y="371" font-size="11.5" fill="#cbd5e1" text-anchor="start">menahan tombol 0,6 detik.</text>
  <text x="190" y="214" font-size="15" fill="#dc2626" text-anchor="end" font-weight="700">04 · BERTINDAK</text>
  <text x="190" y="234" font-size="11.5" fill="#cbd5e1" text-anchor="end">Amankan bukti (SHA-256)</text>
  <text x="190" y="249" font-size="11.5" fill="#cbd5e1" text-anchor="end">→ isolasi ≈1,2 detik</text>
  <text x="190" y="264" font-size="11.5" fill="#cbd5e1" text-anchor="end">→ LAPSIT otomatis.</text>
</svg>
<p class="keterangan"><em>Siklus OODA Nusantara Shield. Mesin mengamati dan mengorientasikan; <strong>manusia memutuskan</strong>; server bertindak dalam urutan yang dikunci.</em></p>
</div>

---

## 5. Kelayakan Penerapan di Lingkungan Satuan

<div class="ilustrasi" id="ilustrasi-berdaulat" style="max-width:62%;margin-left:auto;margin-right:auto">
<svg viewBox="0 0 760 330" width="100%" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Mode Berdaulat: Nusantara Shield berjalan luring penuh di jaringan tertutup satuan tanpa layanan awan" style="font-family:Inter,'Segoe UI','DejaVu Sans',Arial,sans-serif">
  <defs>
    <radialGradient id="mdBg" cx="50%" cy="45%" r="70%"><stop offset="0" stop-color="#13284a"/><stop offset="1" stop-color="#0b1a33"/></radialGradient>
    <pattern id="mdGrid" width="24" height="24" patternUnits="userSpaceOnUse"><path d="M24 0H0V24" fill="none" stroke="#64748b" stroke-opacity=".12" stroke-width="1"/></pattern>
    <marker id="mdPanah" viewBox="0 0 10 10" refX="7" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#f5c451"/></marker>
  </defs>
  <rect width="760" height="330" rx="12" fill="url(#mdBg)"/>
  <rect width="760" height="330" rx="12" fill="url(#mdGrid)"/>
  <defs>
    <radialGradient id="mdKubah" cx="50%" cy="100%" r="100%"><stop offset="0" stop-color="#10b981" stop-opacity=".2"/><stop offset="1" stop-color="#10b981" stop-opacity=".03"/></radialGradient>
    <pattern id="mdHeks" width="22" height="38" patternUnits="userSpaceOnUse"><path d="M11 0L22 6.3V19L11 25.3L0 19V6.3ZM11 25.3V38" fill="none" stroke="#10b981" stroke-opacity=".13" stroke-width="1"/></pattern>
  </defs>
  <text x="380" y="28" font-size="17" font-weight="800" fill="#f1f5f9" text-anchor="middle" letter-spacing="1.5">MODE BERDAULAT · BERJALAN LURING PENUH</text>
  <text x="380" y="47" font-size="11.5" fill="#94a3b8" text-anchor="middle">Tidak ada data maupun ketergantungan yang keluar dari jaringan satuan</text>
  <path d="M130 292A250 228 0 0 1 630 292Z" fill="url(#mdKubah)"/>
  <path d="M130 292A250 228 0 0 1 630 292Z" fill="url(#mdHeks)"/>
  <path d="M130 292A250 228 0 0 1 630 292" fill="none" stroke="#10b981" stroke-width="2.2"/>
  <ellipse cx="380" cy="292" rx="258" ry="7" fill="#10b981" fill-opacity=".15" stroke="#10b981" stroke-opacity=".5"/>
  <text x="380" y="102" font-size="11" font-weight="700" fill="#10b981" text-anchor="middle" letter-spacing="2.5">JARINGAN TERTUTUP SATUAN</text>
  <rect x="326" y="114" width="108" height="170" rx="6" fill="#13284a" stroke="#10b981" stroke-width="1.6"/>
  <text x="380" y="135" font-size="9.5" font-weight="700" fill="#f5c451" text-anchor="middle" font-family="ui-monospace,Menlo,Consolas,'DejaVu Sans Mono',monospace" letter-spacing=".5">NUSANTARA SHIELD</text>
  <rect x="336" y="150" width="88" height="18" rx="2.5" fill="#0b1a33" stroke="#64748b" stroke-width="1"/><circle cx="346" cy="159" r="2.4" fill="#10b981"/><circle cx="354" cy="159" r="2.4" fill="#10b981" fill-opacity="1"/><path d="M366 159H414" stroke="#94a3b8" stroke-opacity=".5" stroke-dasharray="3 2"/><rect x="336" y="174" width="88" height="18" rx="2.5" fill="#0b1a33" stroke="#64748b" stroke-width="1"/><circle cx="346" cy="183" r="2.4" fill="#10b981"/><circle cx="354" cy="183" r="2.4" fill="#10b981" fill-opacity="0.4"/><path d="M366 183H414" stroke="#94a3b8" stroke-opacity=".5" stroke-dasharray="3 2"/><rect x="336" y="198" width="88" height="18" rx="2.5" fill="#0b1a33" stroke="#64748b" stroke-width="1"/><circle cx="346" cy="207" r="2.4" fill="#10b981"/><circle cx="354" cy="207" r="2.4" fill="#10b981" fill-opacity="1"/><path d="M366 207H414" stroke="#94a3b8" stroke-opacity=".5" stroke-dasharray="3 2"/><rect x="336" y="222" width="88" height="18" rx="2.5" fill="#0b1a33" stroke="#64748b" stroke-width="1"/><circle cx="346" cy="231" r="2.4" fill="#10b981"/><circle cx="354" cy="231" r="2.4" fill="#10b981" fill-opacity="0.4"/><path d="M366 231H414" stroke="#94a3b8" stroke-opacity=".5" stroke-dasharray="3 2"/><rect x="336" y="246" width="88" height="18" rx="2.5" fill="#0b1a33" stroke="#64748b" stroke-width="1"/><circle cx="346" cy="255" r="2.4" fill="#10b981"/><circle cx="354" cy="255" r="2.4" fill="#10b981" fill-opacity="1"/><path d="M366 255H414" stroke="#94a3b8" stroke-opacity=".5" stroke-dasharray="3 2"/>
  <circle cx="316" cy="192" r="7" fill="#10b981" fill-opacity=".18" stroke="#10b981" stroke-width="1.3"/><path d="M312.8 192L315 194.6L319.6 189.2" fill="none" stroke="#10b981" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><text x="302" y="196" font-size="11.5" fill="#f1f5f9" text-anchor="end" font-weight="700"><tspan font-style="italic">Server</tspan> lokal</text><text x="302" y="211" font-size="10.5" fill="#94a3b8" text-anchor="end">FastAPI · 1 proses Python</text><circle cx="316" cy="242" r="7" fill="#10b981" fill-opacity=".18" stroke="#10b981" stroke-width="1.3"/><path d="M312.8 242L315 244.6L319.6 239.2" fill="none" stroke="#10b981" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><text x="302" y="246" font-size="11.5" fill="#f1f5f9" text-anchor="end" font-weight="700">Data latihan sintetis</text><text x="302" y="261" font-size="10.5" fill="#94a3b8" text-anchor="end">alamat RFC 5737</text><circle cx="444" cy="192" r="7" fill="#10b981" fill-opacity=".18" stroke="#10b981" stroke-width="1.3"/><path d="M440.8 192L443 194.6L447.6 189.2" fill="none" stroke="#10b981" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><text x="458" y="196" font-size="11.5" fill="#f1f5f9" text-anchor="start" font-weight="700">Bukti dan log audit HMAC</text><text x="458" y="211" font-size="10.5" fill="#94a3b8" text-anchor="start">disimpan di <tspan font-style="italic">server</tspan> sendiri</text><circle cx="444" cy="242" r="7" fill="#10b981" fill-opacity=".18" stroke="#10b981" stroke-width="1.3"/><path d="M440.8 242L443 244.6L447.6 239.2" fill="none" stroke="#10b981" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><text x="458" y="246" font-size="11.5" fill="#f1f5f9" text-anchor="start" font-weight="700">Antarmuka tanpa CDN</text><text x="458" y="261" font-size="10.5" fill="#94a3b8" text-anchor="start">& tanpa font eksternal</text>
  <path d="M104 152C130 152 140 172 165.4 172" fill="none" stroke="#94a3b8" stroke-width="2.4" stroke-dasharray="6 5" stroke-opacity=".7"/><circle cx="136" cy="162" r="11" fill="#0b1a33" stroke="#dc2626" stroke-width="2"/><path d="M131 157L141 167M141 157L131 167" stroke="#dc2626" stroke-width="2.6" stroke-linecap="round"/>
  <path d="M656 152C630 152 620 172 594.6 172" fill="none" stroke="#94a3b8" stroke-width="2.4" stroke-dasharray="6 5" stroke-opacity=".7"/><circle cx="624" cy="162" r="11" fill="#0b1a33" stroke="#dc2626" stroke-width="2"/><path d="M619 157L629 167M629 157L619 167" stroke="#dc2626" stroke-width="2.6" stroke-linecap="round"/>
  <path d="M22 162H100A16 16 0 0 0 96 136A22 22 0 0 0 56 128A18 18 0 0 0 26 142A14 14 0 0 0 22 162Z" fill="#13284a" stroke="#94a3b8" stroke-width="1.6" stroke-opacity=".8"/><text x="62" y="188" font-size="10.5" fill="#94a3b8" text-anchor="middle">Layanan awan / API luar</text>
  <text x="62" y="202" font-size="10.5" fill="#94a3b8" text-anchor="middle">tidak dipakai</text>
  <path d="M658 162H736A16 16 0 0 0 732 136A22 22 0 0 0 692 128A18 18 0 0 0 662 142A14 14 0 0 0 658 162Z" fill="#13284a" stroke="#94a3b8" stroke-width="1.6" stroke-opacity=".8"/><text x="698" y="188" font-size="10.5" fill="#94a3b8" text-anchor="middle">CDN dan fon eksternal</text>
  <text x="698" y="202" font-size="10.5" fill="#94a3b8" text-anchor="middle">tidak dipakai</text>
  <text x="380" y="318" font-size="11" fill="#94a3b8" text-anchor="middle">Internet hanya dibutuhkan sekali, saat memasang dependensi (<tspan font-family="ui-monospace,Menlo,Consolas,'DejaVu Sans Mono',monospace">pip install</tspan>)</text>
</svg>
<p class="keterangan"><em><strong>Mode Berdaulat:</strong> seluruh sistem, data, bukti, dan log berada di dalam jaringan tertutup satuan.</em></p>
</div>

### 5.1 Kedaulatan Sistem dan Mode Hybrid/Luring

> **"Berjalan luring penuh" merujuk pada Aplikasi Inti (Nusantara Shield Core v5.4.0)**, yaitu purwarupa yang diserahkan dan didemonstrasikan dalam lomba ini.

- **Tidak membutuhkan awan atau _server_ luar untuk beroperasi.** Seluruh pemrosesan berjalan di _server_ atau laptop milik satuan (*on-premise*): layanan web, penyimpanan akun dan data (berkas lokal), sidik jari SHA-256 barang bukti, log audit HMAC, tombol isolasi, LAPSIT, dan AI deteksi anomali. Kode _server_ tidak memuat satu pun pemanggilan ke alamat luar.
- **Tanpa ketergantungan eksternal di layar.** Antarmuka tidak memanggil skrip CDN, Google Fonts, atau sumber daring apa pun. Bila internet diputus, dasbor dan _playbook_ respons insiden tetap berjalan penuh. Bahkan bila kabel LAN dicabut, _server_ dan dasbor di laptop yang sama tetap bekerja.
- **Pemasangan tanpa internet sama sekali.** Paket pasang luring berisi kode dan seluruh pustaka, dilengkapi daftar sidik jari SHA-256. Di posko, sidik jari dicocokkan dengan berita acara serah terima paket; satu berkas saja berbeda, pemasangan dihentikan. Paket dibawa lewat media yang sudah diperiksa, sehingga siap untuk jaringan *air-gapped*.
- **Mode Hybrid (rancangan lanjutan, belum ada di purwarupa).** Satu-satunya data yang direncanakan melintasi batas jaringan adalah **umpan indikator ancaman resmi** (BSSN/MISP). Umpan masuk satu arah lewat gerbang yang dikendalikan satuan, atau diimpor sebagai berkas lewat media yang diperiksa. Aplikasi inti tetap luring. Pada purwarupa, umpan CTI memakai data latihan sintetis.
- **Batas purwarupa.** Pengambilan bukti dan pemutusan jaringan **disimulasikan** atas aset latihan. Yang berjalan nyata: penguncian urutan di _server_, perhitungan sidik jari SHA-256, buku berantai HMAC, LAPSIT, korelasi CTI, dan penilaian AI lokal (atas ciri lalu lintas sintetis).
- **Dua jenis AI, dengan status yang berbeda:**
    - **(a) Mesin Deteksi Anomali — sudah beroperasi penuh di purwarupa.** Model _machine learning_ ringan (_Isolation Forest_, scikit-learn) dilatih dan dijalankan 100% luring di _backend_, lalu memberi skor anomali lalu lintas IT dan OT setiap detik. Ini **_local inference_**: tidak ada unduhan model, tidak ada pemanggilan Application Programming Interface (API) luar, dan setelah pemasangan tidak butuh internet sama sekali. Karena itu ia siap untuk **penerapan _air-gapped_**: paket pustakanya cukup dibawa lewat media yang diperiksa. Ciri lalu lintasnya di purwarupa masih sintetis.
    - **(b) Mesin Asisten Narasi — peta jalan, belum ada di purwarupa.** Model bahasa lokal (_Local LLM_) **Llama 3 8B lewat Ollama** untuk menyusun draf LAPSIT. Rencananya juga _local inference_: model dihitung di _server_ satuan, dan untuk satuan _air-gapped_ berkas modelnya diunduh sekali lalu dibawa lewat media yang diperiksa. Model berat ini sengaja **tidak** dimasukkan ke _server_ inti agar beban CPU tetap hemat.
    - Dalam kedua jenis, AI hanya menyarankan dan menaikkan status; memutus jaringan tetap keputusan Operator.
- **AI sebagai alat pengembang.** Selain itu, asisten AI dipakai untuk membantu menulis kode dan dokumentasi, sebagaimana diizinkan panitia (lihat 6.2).

### 5.2 Kesiapan Penerapan

- **Ringan:** satu laptop atau _server_ kecil; satu proses Python. Untuk 300 layar serentak, CPU _server_ ≈1,5% saat siaga dan ≈1,7% saat serangan, dengan memori ≈207 MB termasuk pustaka AI (scikit-learn dan numpy), jauh di bawah 512 MB; diukur ulang 26 Okt 2026 dengan `tools/ukur_beban.py` (Linux 2 inti, 300 siaran SSE sungguhan). AI menambah kerja _server_ hanya ≈0,05 milidetik per detik karena model baru dijalankan saat keadaan lalu lintas berubah.
- **Teruji:** 411 uji otomatis mengunci setiap aturan, termasuk ambang deteksi yang tertulis di dokumen ini, dan dapat dijalankan ulang oleh siapa pun dalam kurang dari satu menit (≈30 detik di Mac, ≈55 detik di Linux ruang kerja awan).
- **Cakupan OT saat ini:** purwarupa memantau **pengendali genset rumah sakit** (Modbus/TCP, _port_ 502) di **zona kendali** topologi. Kabar ancaman Modbus menaikkannya ke **WASPADA (≈66%)** sebelum ada serangan. Pada skenario **Sabotase OT**, bukti diamankan, lalu jalur kantor → zona kendali diputus lewat _webhook_ (simulasi) ke sakelar terkelola ≈1,2 detik kemudian; genset tetap menyala dengan kendali lokal. Pemulihan jalur kendali terkunci sampai sidik jari bukti cocok.
- **Langkah lanjutan** (semuanya sumber terbuka dan dapat berjalan _air-gapped_ atau _on-premise_):
    - telemetri nyata dari sensor dan SIEM satuan (Wazuh, Suricata, Zeek) serta sensor protokol industri Modbus/DNP3;
    - sambungan _webhook_ terautentikasi ke sakelar terkelola sungguhan;
    - pertukaran CTI dengan Badan Siber dan Sandi Negara (BSSN) dan Kartika Computer Security Incident Response Team (CSIRT) lewat Malware Information Sharing Platform (MISP) atau OpenCTI (STIX/TAXII), menggantikan rancangan Mode Hybrid;
    - peristiwa identitas nyata (_login_, perubahan hak akses, akun baru di luar jam kerja) dari Active Directory atau SIEM satuan. Aturan _login_ gagal berulang dan _login_ tembus sudah berjalan, tetapi baru atas peristiwa sintetis;
    - **respons bertingkat menurut kritikalitas aset**: aset vital (SIMRS, pengendali genset, _server_ inti) tetap memakai dua kunci; _endpoint_ kantor berisiko rendah dapat diisolasi otomatis berdasarkan _playbook_ praotorisasi yang ditetapkan Kasi Siber, tetap dengan bukti diamankan lebih dulu dan tercatat di LAPSIT;
    - saat tersambung ke perangkat nyata: brankas kredensial, hak minimum per _playbook_, _playbook_ bertanda tangan digital, dan persetujuan dua orang untuk mengubah _playbook_;
    - akuisisi bukti nyata (misalnya Velociraptor), dan penerusan kasus ke _case management_ (TheHive) beserta label MITRE ATT&CK yang sudah ada;
    - AI: ciri lalu lintas nyata dari sensor satuan untuk Mesin Deteksi Anomali, dan Mesin Asisten Narasi (Llama 3 8B lewat Ollama) untuk draf LAPSIT, dengan _human-in-the-loop_;
    - paket pemasangan luring siap pakai, SSO instansi dengan verifikasi dua langkah, dan operasi multiproses.

### 5.3 Konsep Penempatan dan Pengguna (Usulan)

Nusantara Shield dirancang dipasang **di posko siber atau _Security Operations Center_ (SOC) setiap satuan yang memiliki aset vital**, dengan satu _server_ luring per satuan, dan dioperasikan oleh unsur siber yang sudah ada dalam struktur Tentara Nasional Indonesia Angkatan Darat (TNI AD). Dalam kerangka tiga lapis komando siber (strategis, operasional, dan taktis; Purbo dan Lumy, 2025), Nusantara Shield adalah alat **lapis taktis**, yaitu _Cyber Defense Operation Center_ (CDOC) di tingkat satuan. Konsep ini disusun dari struktur yang disampaikan secara resmi dan **belum diuji di lingkungan TNI AD**.

| Tingkat | Unsur | Peran terhadap Nusantara Shield |
| --- | --- | --- |
| **Satuan** (rumah sakit TNI AD; lapis taktis) | Operator jaga (petugas TI rumah sakit atau Bintara Siber), Kasi Siber, Komandan Satuan (Dansat) | Operator memantau dan menahan tombol isolasi; Kasi Siber menetapkan _playbook_ praotorisasi; Dansat menerima LAPSIT sebagai Pengamat. |
| **Komando Daerah Militer (Kodam)** | Sandi dan Siber Kodam (Sansidam), melalui Tim Penangkalan Siber | Pendamping dan cadangan Operator; meneruskan laporan ke pusat. |
| **Pusat** (lapis operasional) | Satuan pelaksana penangkalan Pussiberad dan Kartika CSIRT | Menerima LAPSIT dan berita acara bukti; menganalisis bukti; menyebarkan kabar ancaman ke satuan. |

- **SOC dan ruang komando:** SOC memakai seluruh dasbor setiap hari. Saat krisis, ruang komando cukup menampilkan Executive Overview, Peta Global, dan LAPSIT dengan akun Pengamat.
- **Kebutuhan minimum per satuan:** satu laptop atau PC (2 inti, 512 MB memori bebas), jaringan internal, minimal dua akun Operator dan satu akun Pengamat.
- **Batas peran:** Nusantara Shield hanya untuk jaringan dan aset milik TNI AD. Insiden pada instansi sipil, BUMN, atau pemerintah daerah ditangani BSSN, Komdigi, dan Polri; TNI baru turun bila yang diserang aset militer atau ancamannya sudah setingkat pertahanan negara. Kasus PDNS 2024 dipakai sebagai **pelajaran** tentang tanda bahaya yang terlambat ditindak, bukan sebagai wilayah tugas sistem ini.
### 5.4 Status Fitur: Sudah Berjalan dan Peta Jalan

Pembedaan ini sengaja dibuat tegas agar juri dapat menilai apa yang benar-benar didemonstrasikan.

| Sudah berjalan di purwarupa v5.4.0 | Belum dibangun (peta jalan: Mode Hybrid dan eskalasi) |
| --- | --- |
| Operasi luring penuh di satu satuan/rumah sakit (*on-premise*) | **(1) Pengiriman LAPSIT otomatis berjenjang** ke Sandi dan Siber Kodam (Sansidam) dan Kartika CSIRT (Pussiberad) |
| Dua peran: Pengamat dan Operator | **(2) Akses dan tampilan lintas satuan** untuk pemantauan serentak di Mabes |
| Isolasi dengan tombol yang ditahan 0,6 detik | Mesin Asisten Narasi: LLM lokal Llama 3 8B lewat Ollama untuk draf LAPSIT |
| Rantai bukti HMAC-SHA256 | Umpan indikator resmi (BSSN/MISP) lewat gerbang satu arah |
| Korelasi CTI dan Mesin Deteksi Anomali (_Isolation Forest_, luring) | Aliran langsung dari sensor (Wazuh, Suricata, Zeek; kini lewat impor berkas keluarannya) dan sakelar terkelola sungguhan |
| Simulasi OT genset (Modbus, _port_ 502) | Peristiwa identitas nyata dari Active Directory (perubahan hak akses, akun baru) |
| Pembuatan LAPSIT dan ekspor PDF | Pengamanan integrasi nyata: brankas kredensial, hak minimum per _playbook_, _playbook_ bertanda tangan |
| Paket pasang luring bersidik jari SHA-256 (tanpa internet sama sekali) | **Respons bertingkat menurut kritikalitas aset:** aset vital tetap dua kunci; _endpoint_ kantor berisiko rendah diisolasi otomatis dengan praotorisasi |
| Mesin Deteksi Aturan: _login_ gagal berulang, _login_ tembus, pemindaian _port_, koneksi IT ke zona kendali OT tanpa izin, dan perintah tulis Modbus di luar jendela pemeliharaan (ambang terbuka; atas peristiwa sintetis) | |
| **Impor log luring** (auth.log OpenSSH, log firewall UFW/iptables, CSV, serta keluaran sensor **Wazuh `alerts.json`** dan **Suricata `eve.json`**; maks. ≈2 MB) dinilai Mesin Deteksi Aturan yang sama; temuan berlabel sumber berkasnya | |
| Label teknik MITRE ATT&CK (termasuk ATT&CK for ICS) di peringatan, log, dan LAPSIT; label sumber data di setiap peringatan; pengesahan dua tanda tangan di LAPSIT PDF | |
| Linimasa 60 menit (data latihan), pita anomali AI per aset, KPI Waktu respons (MTTC) dan Insiden sejak posko aktif | |
| Nilai Kesiapan Siber A–E (dua sub-skor: Kerawanan dan Insiden) dan triase peringatan: Selesai ditangani atau Positif Palsu (_False Positive_), beralasan dan tercatat di Buku Rantai Bukti | |
| **Drill Kesiapan** untuk Operator: log sintetis lewat aturan deteksi yang sama, pertanyaan per fase penanganan insiden, nilai 0–100 dari jejak tercatat (dua skenario: cadangan dilepas lewat auth.log; perintah asing ke genset lewat Suricata `eve.json`) | **_Tabletop exercise_ untuk pimpinan** (Dansat, Kepala RS): *inject* bertahap, doktrin sebagai rubrik; skenario drill lain (*phishing*, perubahan halaman situs satuan) |

### 5.5 Peta Jalan Penguatan dari Studi Banding Arsitektur

Pada 30 Oktober 2026, keempat pilar Nusantara Shield dibandingkan dengan proyek sumber terbuka dan makalah yang relevan. Hasilnya empat penguatan berikut. Yang pertama **sudah dibangun di v5.4.0**; tiga lainnya **belum dibangun**:

| Gagasan | Pilar | Masalah yang dijawab | Rujukan studi banding |
| --- | --- | --- | --- |
| **Evolusi kunci audit dan titik periksa bertanda tangan Ed25519** (**sudah dibangun, v5.3.0**: titik periksa Ed25519 dengan kunci berevolusi; kunci HMAC sendiri belum berevolusi) | Integritas bukti | HMAC memakai satu kunci rahasia untuk membuat sekaligus memeriksa. Bila _server_ dibobol, penyerang yang memegang `NS_AUDIT_KEY` bisa menulis ulang riwayat dengan sidik jari yang sah. Kunci yang berevolusi per periode (kunci lama dihapus) membuat catatan masa lalu tidak bisa dipalsukan (_forward security_); titik periksa Ed25519 berkala memungkinkan auditor memeriksa hanya dengan kunci publik | Makalah Nitro (ACM CCS 2025); Trillian dan immudb (log terverifikasi) |
| **Batas waktu _fail-safe_ dan aturan dua orang** untuk tindakan pemutus | Doktrin Dua Kunci | Setiap tindakan pemutus menjadi Permintaan Otorisasi bernomor yang terikat ke SHA-256 bukti. Kedaluwarsa berarti **tidak dieksekusi** dan tercatat sebagai KEDALUWARSA; untuk aset vital, penyetuju harus akun yang berbeda dari pengusul | StackStorm _Inquiries_ (validasi jawaban, TTL); Shuffle (pemicu _User Input_ dengan pilihan lanjutkan/batalkan) |
| **Garis dasar Modbus** | Konvergensi IT/OT | Peristiwa OT dinormalkan ke format pesan bersama berbasis aktivitas (tanya, jawab, **perintah**), sehingga aturan berlaku lintas protokol (Modbus kini, DNP3 kelak). Pola _polling_ dipelajari per pasangan sumber–unit dengan rerata dan simpangan yang diperbarui per peristiwa (algoritma Welford), lalu jeda yang terlalu pendek (skor-Z tinggi) menaikkan WASPADA; ditambah peta rentang register yang sah. Garis dasar baru berlaku setelah **disahkan Operator** | IPAL (RAID 2022); _ics-anomaly-detection_ (profil frekuensi _polling_) |
| **Paket intelijen bertanda tangan** | Luring | Indikator CTI dan ambang aturan dikirim sebagai berkas terpisah yang diverifikasi kunci rilis yang sama (Ed25519) sebelum diimpor, sehingga intelijen bisa diperbarui lewat media yang diperiksa tanpa internet | Security Onion (pembaruan aturan lewat ISO pada mode _air-gap_) |

Semua gagasan di atas ditulis dari nol; yang diambil dari proyek rujukan hanya konsepnya. Titik periksa Ed25519 dibangun lebih dulu (v5.4.0, Dokumentasi Teknis §2.7.1), karena menutup kelemahan nyata pada pilar integritas bukti; tiga gagasan lainnya belum dibangun.

---

## 6. Deklarasi Karya dan Atribusi

### 6.1 Riwayat Pengembangan

Sesuai Rulebook Kartika Cyber Hackathon 2026 bagian G (Ketentuan Karya), tim menyatakan bahwa seluruh kode Nusantara Shield **dikembangkan sejak 15 Oktober 2026**, setelah publikasi program (12 Oktober 2026), mulai dari versi 1 hingga versi 5.1 yang diserahkan. Selain pustaka sumber terbuka yang tercantum pada 6.2, tidak ada kode dari karya pihak lain atau karya tim yang dibuat sebelum tanggal tersebut.

### 6.2 Atribusi Pustaka dan Alat

Sesuai Rulebook bagian G (Ketentuan Karya), berikut pustaka dan alat pihak ketiga yang digunakan:

| Komponen | Kegunaan | Lisensi |
| --- | --- | --- |
| **FastAPI** (beserta Starlette dan Pydantic) | Kerangka _server_ dan validasi masukan | MIT dan BSD-3-Clause |
| **Uvicorn** | _Server_ web asinkron | BSD-3-Clause |
| **ReportLab** | Ekspor LAPSIT ke PDF | BSD |
| **pytest** dan **HTTPX** | Uji otomatis | MIT dan BSD-3-Clause |
| **Mermaid** dan **Playwright (Chromium)** | Hanya untuk menggambar diagram dan mencetak dokumen ini; tidak dipakai aplikasi | MIT, Apache-2.0, dan BSD-3-Clause |
| **scikit-learn** dan **NumPy** | Mesin Deteksi Anomali (_Isolation Forest_), berjalan lokal | BSD-3-Clause |
| **Lucide** (v0.460.0) | Ikon pada poster, disematkan sebagai SVG sebaris; tidak dipakai aplikasi | ISC |
| **Claude (Anthropic)** | Asisten AI untuk membantu menulis kode dan dokumentasi; tidak dipanggil oleh aplikasi | Layanan komersial |
| **MITRE ATT&CK®** (Enterprise dan ICS) | Label teknik pada peringatan dan LAPSIT; tabel statis di `app/mitre.py`, pemetaan oleh tim sendiri | Merek dagang The MITRE Corporation; dipakai sebagai rujukan |
| **Gemini (Google)** | Eksplorasi awal konsep logo; logo final digambar ulang tim sebagai vektor SVG dan tidak memuat gambar hasil AI | Layanan komersial |
| **Inter** dan **JetBrains Mono** | Huruf pada logo horizontal dan spanduk README | SIL Open Font License 1.1 |
| **Blok alamat Internet Protocol (IP) Request for Comments (RFC) 5737** | Data latihan sintetis | Standar terbuka IETF |

### 6.3 Lisensi

Kode Nusantara Shield dilisensikan di bawah **GNU General Public License v3.0** (`GPL-3.0-only`, berkas `LICENSE`), Copyright (c) 2026 Nusantara Shield Team. Hak cipta tetap milik tim; turunan yang disebarkan wajib tetap berlisensi GPLv3 dan mencantumkan hak cipta tim. Lisensi ini sejalan dengan Rulebook bagian N: Penyelenggara tetap mendapat lisensi non-eksklusif untuk menampilkan dan mempromosikan karya, dan Pussiberad dapat mengadopsi pendekatannya untuk pertahanan siber.

### 6.4 Rujukan Kerangka

- Purbo, O. W., dan Lumy, G. D. (2025). _Cyber Warfare & Pertahanan Siber Indonesia_. Kerangka OODA, tiga lapis komando siber, _incident response_ militer, dan _After-Action Review_.
- Peraturan Presiden Nomor 82 Tahun 2022 tentang Pelindungan Infrastruktur Informasi Vital: Pasal 4 (sektor kesehatan dan pertahanan) dan Pasal 15 (simulasi tanggap Insiden Siber), dasar Drill Kesiapan.
- Satuan Siber TNI. _Visi dan Misi_. satsiber-tni.mil.id/visi-dan-misi-20181230531, diakses 9 November 2026.
- National Institute of Standards and Technology (NIST) SP 800-61, panduan penanganan insiden keamanan komputer: fase deteksi dan analisis serta penahanan, pembersihan, dan pemulihan dipakai sebagai susunan pertanyaan Drill Kesiapan.
- National Institute of Standards and Technology (NIST) SP 800-82, panduan keamanan sistem kendali industri (OT).
- International Organization for Standardization/International Electrotechnical Commission (ISO/IEC) 27037:2012, pedoman identifikasi, pengumpulan, akuisisi, dan pelestarian bukti digital. Alur "bukti dulu, baru putus" dan buku berantai HMAC disusun **mengikuti prinsipnya**; purwarupa belum diaudit terhadap standar ini.
- Wolsing, K., Wagner, E., Saillard, A., dan Henze, M. (2022). _IPAL: Breaking up Silos of Protocol-dependent and Domain-specific Industrial Intrusion Detection Systems_. RAID 2022. Rujukan format pesan OT lintas protokol (§5.5, peta jalan).
- Zhao, R., Shoaib, M., Hoang, V. T., dan Hassan, W. U. (2025). _Rethinking Tamper-Evident Logging: A High-Performance, Co-Designed Auditing System_ (Nitro). ACM CCS 2025. Rujukan _forward security_ untuk log audit (§5.5, peta jalan).
- National Institute of Standards and Technology (2024). _The NIST Cybersecurity Framework (CSF) 2.0_ (NIST CSWP 29). Enam fungsi dan kategorinya dipakai untuk **memetakan** fitur (Dokumentasi Teknis §2.6); pemetaan dilakukan tim sendiri, bukan sertifikasi.

---

## 7. Peta Kriteria Penilaian dan Asal Angka

Bagian ini memudahkan Dewan Juri memeriksa klaim kami sendiri: setiap kriteria Rulebook (bagian H) dipetakan ke bukti di karya, dan setiap angka di dokumen, slide, dan poster ditautkan ke sumbernya.

### 7.1 Peta Kriteria Penilaian

| Kriteria (bobot) | Bukti di Nusantara Shield | Cara memeriksa |
| --- | --- | --- |
| **Relevansi dan Manfaat** (25%) | Menjaga aset IT dan OT rumah sakit TNI AD dalam satu layar; alat lapis taktis (CDOC satuan) dengan LAPSIT untuk Dansat; usulan alur laporan ke Sansidam dan Kartika CSIRT (§5.3); label satuan diatur dari satu kamus istilah | §2 dan §5.3 dokumen ini; Dokumentasi Teknis §3 (SOP respons insiden) |
| **Inovasi Teknis** (25%) | "Bukti dulu, baru putus" dikunci _server_ (isolasi tanpa bukti ditolak 409); rantai HMAC-SHA256 untuk log audit dan Buku Rantai Bukti; dua kunci (mesin hanya menaikkan WASPADA, manusia memutus); AI _Isolation Forest_ luring yang menjelaskan alasannya; korelasi kabar ancaman × aset sebelum serangan; aturan OT deterministik (jalur IT ke OT tanpa izin, perintah tulis Modbus di luar jendela pemeliharaan) yang hanya menaikkan WASPADA; label MITRE ATT&CK; isolasi OT dengan memutus **jalur**, bukan mematikan genset; siaran ralat (_delta_) yang menekan beban _server_ | Uji `test_rantai_bukti` (36), `test_ai` (10), `test_ot` (6), `test_deteksi` (24), `test_ot_mitre_lapsit` (23); Dokumentasi Teknis §2.3–2.8 |
| **Fungsionalitas Purwarupa** (25%) | Aplikasi berjalan penuh dari satu perintah; 4 skenario latihan dan latihan deteksi di dasbor; **impor log asli** (auth.log OpenSSH, log firewall, CSV) dinilai aturan yang sama; **Drill Kesiapan** bernilai untuk Operator; 411 uji otomatis lulus; paket luring dipasang dan diuji tanpa internet di Mac dan di Ubuntu 24.04 (paket bertanda tangan). **Batas yang kami akui:** telemetri langsung dan kabar ancaman masih sintetis (log asli baru masuk lewat impor berkas, belum sensor terus-menerus), dan perintah ke sakelar jaringan masih simulasi | `./run_tests.sh`; halaman rilis v5.1.2 beserta sidik jari paket; video demo |
| **Kelayakan Implementasi** (15%) | Satu proses Python di laptop atau _server_ kecil; ≈1,5% CPU untuk 300 layar; berjalan dan dipasang tanpa internet dengan sidik jari SHA-256, dan untuk Ubuntu 24.04 dengan paket bertanda tangan Ed25519 serta layanan systemd yang dikeraskan; peran Operator dan Pengamat; peta jalan ke sensor sumber terbuka (Wazuh, Suricata, Zeek) dan MISP | §5 dokumen ini; Dokumentasi Teknis §4.4 (pemasangan luring) |
| **Kualitas Dokumentasi** (10%) | Proposal ini, Dokumentasi Teknis, Panduan Belajar (PDF), dek presentasi, poster A4, README, CHANGELOG per perubahan, dan deklarasi serta atribusi (§6) | Folder `docs/` dan `presentation/` di repositori |

### 7.2 Asal Setiap Angka

| Angka | Artinya | Sumber | Catatan |
| --- | --- | --- | --- |
| **≈66% → ≈20%** | Peluang serangan pengendali genset setelah kabar celah Modbus, sebelum dan sesudah Perketat | Rumus korelasi di `app/telemetri.py` (0,80 × 0,75 × 1,1 ≈ 66%); dikunci `test_ot` (60–70%, lalu di bawah 30%) | Kabar ancaman dan bobotnya data latihan sintetis |
| **≈1,2 detik** | **Satu definisi untuk semua dokumen:** dari Operator selesai menahan tombol sampai jalur pertama diputus. Bukti diamankan di awal jeda itu | Konstanta `JEDA_RUNBOOK = 1.2` di `app/telemetri.py`; urutannya dikunci `test_ot` dan `test_rantai_bukti` | Waktu alur di purwarupa. Pengambilan bukti tersimulasi (seketika) dan pemutusan ke sakelar masih simulasi. Di produksi, total waktu = lama pengambilan bukti + 1,2 detik (Dokumentasi Teknis §3.2) |
| **0,6 detik** | Lama tombol isolasi harus ditahan Operator | `static/app.js` (tahan 600 ms) | Mencegah klik tak sengaja |
| **8 kali / 60 detik**, **≤120 detik**, **15 kombinasi / 10 detik** | Ambang _login_ gagal berulang, _login_ tembus, dan pemindaian _port_ | `app/deteksi.py`; dikunci `test_deteksi::test_ambang_terbuka_sesuai_dokumentasi` | Dihitung atas peristiwa sintetis |
| **22.00–02.00**, **600 detik** | Jendela pemeliharaan perintah tulis Modbus, dan jendela rantai IT → OT | `app/deteksi.py`; dikunci `test_ot_mitre_lapsit` (jendela diuji per jam) | Jam pada peristiwa Modbus juga sintetis |
| **≈1,5% siaga · ≈1,7% serangan**, **≈207 MB**, **0,28–0,40 MB/s** | CPU, memori, dan lalu lintas _server_ untuk 300 layar | `tools/ukur_beban.py`, 26 Okt 2026, Linux 2 inti, 300 siaran SSE sungguhan; Dokumentasi Teknis §2.3 | Bisa diulang siapa pun dengan alat yang sama |
| **−80% (8,4 → 1,7 MB/s)** | Efek optimasi siaran ralat | Uji beban 15–17 Okt 2026; Dokumentasi Teknis §2.3 | Riwayat optimasi dengan mesin dan alat ukur awal yang tidak disertakan di repositori; tidak dibandingkan langsung dengan angka versi akhir |
| **≈10 milidetik** | Waktu AI menilai 9 aset | `skor_ms` di `app/ai_anomali.py`; dikunci `test_ai` (di bawah 100 ms) | Ukuran di mesin pengembang; uji sengaja memberi batas longgar |
| **411 uji** | Perilaku yang dikunci uji otomatis | `./run_tests.sh`; 411 lulus pada 9 Nov 2026 (Linux ≈55 detik) | Rilis v5.2.0 (334 uji saat itu) juga lulus semua setelah paket Ubuntu 24.04 bertanda tangan dipasang sebagai root dengan jaringan diputus |
| **200.000 putaran**, **5 percobaan/menit**, **16 KB** | PBKDF2-SHA256 untuk kata sandi, batas _login_, batas kiriman | `app/keamanan.py`; dikunci `test_keamanan` (`test_tebak_sandi_dibatasi`, uji batas kiriman) | — |

## Lampiran: Kamus Istilah

Kamus ini untuk pembaca yang tidak berlatar militer atau teknis. Istilah diurutkan menurut abjad.

| Istilah | Kepanjangan atau arti | Penjelasan sederhana |
| --- | --- | --- |
| **_Air-gapped_** | Jaringan terpisah dari internet | Jaringan yang secara fisik tidak tersambung ke internet sama sekali. |
| **_Cyber drill_** | Latihan tanggap insiden | Simulasi insiden dengan skenario khusus satu organisasi; kecepatan dan ketepatan tim dinilai. Di sistem ini: Drill Kesiapan. |
| **_Explainability_** | Keterjelasan | AI wajib menyebut alasannya dalam bahasa manusia, misalnya "perintah tulis Modbus 10× normal". |
| **_False Positive_** | Positif Palsu | Alarm yang ternyata bukan ancaman. Operator menutupnya dengan alasan tertulis; penutupan tercatat permanen dan tidak menghapus apa pun. |
| **_Hash_ / SHA-256** | Sidik jari digital; SHA-256 = _Secure Hash Algorithm 256-bit_ | Rumus yang mengubah isi berkas menjadi 64 karakter. Isi berubah satu huruf, sidik jarinya berubah total. |
| **_Human-in-the-loop_** | Manusia tetap memegang keputusan | Mesin hanya menyarankan; tindakan memutus jaringan harus disetujui Operator. |
| **_Local inference_** | Perhitungan AI di komputer sendiri | Model dijalankan di _server_ sendiri, bukan lewat layanan di internet. Berbeda dengan _air-gapped_. |
| **_Machine learning_** | Pembelajaran mesin | Komputer belajar pola dari contoh data, bukan dari aturan yang ditulis satu per satu. |
| **_On-premise_** | Terpasang di tempat sendiri | Dipasang di perangkat milik satuan, bukan disewa dari layanan awan. |
| **_Playbook_** | Buku panduan langkah | Urutan tindakan baku untuk setiap jenis insiden. |
| **_Port_** | Pintu layanan | Nomor "pintu" di perangkat; tiap layanan punya nomornya sendiri. |
| **_Ransomware_** | Program penyandera data | Program jahat yang mengunci data lalu meminta tebusan. |
| **_Server_** | Komputer pelayan | Komputer yang melayani komputer lain; di sini tempat Nusantara Shield berjalan. |
| **_Tabletop exercise_** (TTX) | Latihan diskusi skenario | Latihan untuk pimpinan: yang diuji keputusan saat insiden, bukan kemampuan teknis. Masuk peta jalan. |
| **_Webhook_** | Panggilan otomatis | Pesan otomatis dari satu sistem ke sistem lain, misalnya perintah ke sakelar jaringan. |
| **AAR** | _After-Action Review_ (tinjauan pascatindakan) | Rapat evaluasi setelah insiden: apa yang terjadi, apa penyebabnya, dan apa yang diperbaiki. |
| **Action Center** | Pusat tindakan | Panel di dasbor tempat Operator melihat insiden dan menekan tombol isolasi. |
| **AI lokal** | Kecerdasan buatan yang berjalan di komputer sendiri | Model yang dilatih dan dihitung di _server_ satuan, tanpa mengirim data ke internet. |
| **Alamat IP** | Alamat _Internet Protocol_ | Nomor unik setiap perangkat di jaringan, seperti nomor rumah. |
| **API** | _Application Programming Interface_ | "Loket" tempat layar dan _server_ saling meminta data. |
| **Aset** | Barang yang dilindungi | Perangkat atau sistem penting: komputer, _server_, basis data, genset. |
| **ASGI** | _Asynchronous Server Gateway Interface_ | Antarmuka standar antara _server_ web dan aplikasi Python; di sini gerbang yang menolak kiriman terlalu besar sebelum menyentuh logika. |
| **ATT&CK** | _Adversarial Tactics, Techniques, and Common Knowledge_ (MITRE) | Katalog publik taktik dan teknik penyerang; dipakai untuk melabeli peringatan, misalnya T0855. |
| **Bintara Siber** | Prajurit TNI AD berpangkat bintara di bidang siber | Calon Operator harian sistem ini di satuan. |
| **BSSN** | Badan Siber dan Sandi Negara | Lembaga keamanan siber nasional. |
| **CDN** | _Content Delivery Network_ | Layanan luar untuk memuat huruf atau skrip situs web. Nusantara Shield tidak memakainya. |
| **CDOC** | Cyber Defense Operation Center | Pusat operasi pertahanan siber di tingkat satuan. |
| **CPU** | Central Processing Unit | Otak komputer; persentasenya menunjukkan seberapa sibuk _server_. |
| **CSF 2.0** | _Cybersecurity Framework_ 2.0 (NIST) | Kerangka keamanan siber dengan enam fungsi: _Govern_, _Identify_, _Protect_, _Detect_, _Respond_, dan _Recover_. |
| **CSIRT** | _Computer Security Incident Response Team_ | Tim tanggap insiden siber. Kartika CSIRT adalah milik TNI AD. |
| **CSP** | _Content Security Policy_ (kebijakan keamanan konten) | Aturan yang hanya mengizinkan skrip dan gaya milik aplikasi sendiri berjalan di layar. |
| **CTI** | _Cyber Threat Intelligence_ (intelijen ancaman siber) | Kabar dari luar tentang ancaman yang sedang beredar, misalnya celah baru pada suatu perangkat. |
| **Dansat** | Komandan Satuan | Pimpinan unit; di sistem ini berperan sebagai Pengamat yang menerima laporan. |
| **DDoS** | _Distributed Denial of Service_ | Serangan banjir permintaan agar layanan lumpuh karena kewalahan. |
| **Deteksi anomali** | Pengenalan perilaku tidak wajar | Menandai lalu lintas yang menyimpang dari kebiasaan, tanpa perlu daftar serangan yang sudah dikenal. |
| **DMZ** | Demilitarized Zone | Zona penyangga antara internet dan jaringan dalam, seperti lobi. |
| **Drill Kesiapan** | Latihan tanggap insiden bernilai | Log sintetis satu cerita, satu pertanyaan per fase penanganan, nilai 0–100 dari jejak yang tercatat sistem (§3.3). |
| **Enkripsi** | Penyandian data | Mengubah data menjadi sandi. _Ransomware_ memakainya untuk mengunci data korban. |
| **Forensik digital** | Penyelidikan bukti elektronik | Mengamankan dan memeriksa jejak digital agar pelaku bisa ditelusuri dan bukti sah. |
| **HMAC** | _Hash-based Message Authentication Code_ | Segel digital berkunci. Setiap catatan log disegel dan terhubung ke catatan sebelumnya, sehingga perubahan diam-diam langsung ketahuan. |
| **HSTS** | HTTP Strict Transport Security | Aturan agar peramban selalu memakai sambungan terenkripsi. |
| **HTTPS** | Hypertext Transfer Protocol Secure | Sambungan web yang dienkripsi. |
| **IIV** | Infrastruktur Informasi Vital | Sistem elektronik yang gangguannya berdampak serius; menurut Perpres 82/2022 termasuk sektor kesehatan dan pertahanan. |
| **IP** | Internet Protocol | Alamat IP: "nomor kamar" setiap perangkat di jaringan. |
| **ISO/IEC 27037** | International Organization for Standardization/International Electrotechnical Commission, standar 27037:2012 | Pedoman internasional mengidentifikasi, mengumpulkan, mengambil, dan melestarikan bukti digital. Nusantara Shield mengikuti prinsipnya; belum diaudit terhadapnya. |
| **Isolasi** | Pemutusan jaringan | Memutus jalur perangkat yang diserang agar serangan tidak menyebar. |
| **Isolation Forest** | Nama algoritma _machine learning_ | Cara mesin menemukan data yang aneh: data yang tidak wajar paling cepat "terpisah" dari kelompoknya. |
| **IT** | _Information Technology_ (teknologi informasi) | Komputer kantor, _server_, dan jaringannya. |
| **Kesdam** | Kesehatan Daerah Militer | Badan pelaksana kesehatan di tingkat Kodam, membawahi rumah sakit jajaran. |
| **Kesiapan Siber (nilai)** | Rapor A–E kesiapan layanan dan posko | Gabungan dua sub-skor 0–100, Kerawanan dan Insiden; yang dipakai adalah yang lebih rendah. |
| **Kodam** | Komando Daerah Militer | Komando TNI AD tingkat wilayah (provinsi). |
| **LAPSIT** | Laporan Situasi | Laporan resmi singkat tentang insiden: apa, di mana, kapan, dan tindakan yang diambil. |
| **LLM** | _Large Language Model_ (model bahasa besar) | AI penyusun teks, misalnya Llama 3 8B. Di proyek ini masih rencana. |
| **Log audit** | Catatan jejak | Daftar siapa melakukan apa dan kapan di dalam sistem. |
| **Luring** | Di luar jaringan (_offline_) | Berjalan tanpa sambungan internet. |
| **Mabes** | Markas Besar | Markas pusat, misalnya Mabes TNI atau Mabesad (Markas Besar TNI AD). |
| **MISP** | Malware Information Sharing Platform | Platform berbagi kabar ancaman antarlembaga. |
| **ML** | Machine Learning | Cara komputer belajar pola dari contoh data. |
| **Modbus** | Bahasa komunikasi mesin industri | Protokol untuk memerintah mesin seperti genset; memakai _port_ 502. |
| **MTTC** | _Mean Time To Contain_ (rata-rata waktu penahanan) | Rata-rata waktu dari insiden dimulai sampai ancaman ditahan, misalnya jaringan aset terdampak sudah diputus. |
| **NIST** | National Institute of Standards and Technology | Lembaga standar Amerika Serikat; SP 800-82 adalah panduan keamanan sistem industri, dan CSF 2.0 adalah kerangka keamanan siber umumnya. |
| **OODA** | _Observe–Orient–Decide–Act_ | Siklus keputusan: Amati, Orientasi, Putuskan, Bertindak. Siapa yang lebih cepat, dia unggul. |
| **Operator** | Petugas jaga sistem | Satu-satunya peran yang boleh menekan tombol tindakan. |
| **OSINT** | Open Source Intelligence | Intelijen dari sumber terbuka, misalnya berita dan buletin keamanan. |
| **OT** | _Operational Technology_ (teknologi operasional) | Perangkat yang mengendalikan mesin fisik, seperti genset dan catu daya rumah sakit. |
| **PBKDF2** | _Password-Based Key Derivation Function 2_ | Cara menyimpan kata sandi dengan hitungan berulang, sehingga sulit ditebak bila berkasnya bocor. |
| **PDNS** | Pusat Data Nasional Sementara | Pusat data pemerintah yang lumpuh diserang _ransomware_ pada Juni 2024. |
| **Pemindaian _port_** | _Port scan_ | Satu alamat mencoba banyak "pintu" perangkat dalam waktu singkat untuk mencari layanan yang terbuka; sering menjadi tanda awal serangan. |
| **Perketat** | Pengerasan (_hardening_) | Tombol untuk mengurangi celah sebuah aset sebelum diserang. |
| **Perpres** | Peraturan Presiden | Perpres 82/2022 mewajibkan simulasi tanggap insiden siber bagi Penyelenggara IIV (Pasal 15). |
| **Purwarupa** | _Prototype_ | Versi percobaan untuk membuktikan gagasan, belum dipakai di lapangan. |
| **Pussiberad** | Pusat Siber Angkatan Darat | Satuan pusat TNI AD yang menangani pertahanan siber; penyelenggara lomba. |
| **RDP** | Remote Desktop Protocol | Cara mengendalikan komputer dari jarak jauh. |
| **RFC 5737** | Standar alamat IP contoh | Blok alamat IP khusus dokumentasi yang tidak dipakai di internet sungguhan, sehingga aman untuk demo. |
| **RSPAD** | Rumah Sakit Pusat Angkatan Darat (Gatot Soebroto) | Rumah sakit rujukan tertinggi TNI AD di Jakarta. |
| **Sansidam** | Sandi dan Siber Kodam | Unit sandi dan siber di tingkat Kodam yang membantu satuan di wilayahnya. |
| **Satuan** | Unit organisasi militer | Misalnya rumah sakit TNI AD beserta personelnya. |
| **SEV-1** | _Severity 1_ (tingkat keparahan tertinggi) | Label untuk insiden paling gawat. |
| **SIMRS** | Sistem Informasi Manajemen Rumah Sakit | Sistem komputer rekam medis dan layanan pasien. |
| **SOAR** | _Security Orchestration, Automation and Response_ | Otomasi langkah respons keamanan, misalnya pemutusan jalur yang sudah disetujui. |
| **SOC** | _Security Operations Center_ (pusat operasi keamanan) | Ruang dan tim yang memantau keamanan jaringan setiap saat. |
| **SPK** | Sistem pendukung keputusan | Sistem yang menyiapkan informasi dan pilihan tindakan; keputusan akhir tetap di tangan manusia. |
| **SSE** | _Server-Sent Events_ | Cara _server_ mengirim kabar terbaru ke layar secara langsung. |
| **SSH** | Secure Shell | Akses jarak jauh ke _server_ lewat baris perintah. |
| **STIX** | Structured Threat Information Expression | Format standar untuk menulis kabar ancaman. |
| **TAXII** | Trusted Automated Exchange of Intelligence Information | Cara standar mengirim kabar ancaman antarsistem. |
| **TTIS** | Tim Tanggap Insiden Siber | Tim yang menangani insiden siber; di TNI AD, TTIS melayani pemantauan, analisis risiko, penanganan, dan pendampingan pemulihan. |
| **TNI AD** | Tentara Nasional Indonesia Angkatan Darat | Matra darat dari angkatan bersenjata Indonesia. |
| **Uji otomatis** | _Automated test_ | Daftar periksa yang dijalankan komputer untuk memastikan setiap aturan sistem benar. |
| **WASPADA** | Status siaga | Tanda kuning: aset berisiko tinggi diserang, walaupun serangan belum terjadi. |
| **Zona kendali** | Jaringan khusus mesin (OT) | Bagian jaringan tempat pengendali mesin fisik berada, dipisah dari jaringan kantor. |
