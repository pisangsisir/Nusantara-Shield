# Contoh log untuk fitur Impor log

Ketiga berkas ini **sintetis** (alamat IP dari blok dokumentasi RFC 5737) dan hanya contoh format. Fitur **Impor log** di dasbor (bilah Latihan → *Impor log…*, khusus Operator) juga menerima log asli dari *server* satuan.

| Berkas | Format | Yang akan terdeteksi |
| --- | --- | --- |
| `auth.log` | Log autentikasi OpenSSH (syslog) | 10 *login* gagal dari 203.0.113.91 dalam ≈18 detik, lalu *login* berhasil dari alamat yang sama → *login* gagal berulang (T1110) dan *login* tembus (T1078) pada Akses admin SSH |
| `ufw.log` | Log firewall UFW/iptables (`SRC=`, `DST=`, `DPT=`) | 20 *port* berbeda ke Portal web dalam ≈5 detik → pemindaian *port* (T1046) |
| `peristiwa-ot.csv` | CSV berkepala `waktu,jenis,sumber,aset,berhasil,ip,port,fungsi,jam` | Stasiun rekayasa resmi membaca register (bukan temuan); 192.0.2.183 menyeberang ke genset lalu menulis register pukul 14.00 → koneksi OT tanpa izin (T0886), tulis di luar jendela pemeliharaan (T0855), dan rantai IT ke OT |

Aturan yang menilai log impor sama persis dengan aturan latihan (`app/deteksi.py`). Waktu diputar ulang relatif: peristiwa terakhir di log dianggap terjadi saat ini, dan jarak antarperistiwa tetap. Hasilnya hanya menaikkan aset ke WASPADA; isolasi tetap keputusan Operator.

Batas: ≈2 MB dan 50.000 baris per berkas. Nama akun dalam log tidak disimpan, dan isi log tidak masuk log audit (hanya nama berkas dan jumlah baris).
