# Contoh log untuk fitur Impor log

Kelima berkas ini **sintetis** (alamat IP dari blok dokumentasi RFC 5737) dan hanya contoh format. Fitur **Impor log** di dasbor (bilah Latihan → *Impor log…*, khusus Operator) juga menerima log asli dari *server* satuan.

| Berkas | Format | Yang akan terdeteksi |
| --- | --- | --- |
| `auth.log` | Log autentikasi OpenSSH (syslog) | 10 *login* gagal dari 203.0.113.91 dalam ≈18 detik, lalu *login* berhasil dari alamat yang sama → *login* gagal berulang (T1110) dan *login* tembus (T1078) pada Akses admin SSH |
| `ufw.log` | Log firewall UFW/iptables (`SRC=`, `DST=`, `DPT=`) | 20 *port* berbeda ke Portal web dalam ≈5 detik → pemindaian *port* (T1046) |
| `peristiwa-ot.csv` | CSV berkepala `waktu,jenis,sumber,aset,berhasil,ip,port,fungsi,jam` | Stasiun rekayasa resmi membaca register (bukan temuan); 192.0.2.183 menyeberang ke genset lalu menulis register pukul 14.00 → koneksi OT tanpa izin (T0886), tulis di luar jendela pemeliharaan (T0855), dan rantai IT ke OT |
| `wazuh-alerts.json` | Keluaran Wazuh (`/var/ossec/logs/alerts/alerts.json`, JSON per baris) | 10 peringatan `authentication_failed` dari 203.0.113.77 ke agen `simrs-adm`, lalu `authentication_success` → *login* gagal berulang dan *login* tembus. Peringatan agregat Wazuh 5763 (*brute force*), `sudo`, dan FIM **tidak** dihitung: rentetan dinilai aturan kita sendiri dengan ambang terbuka |
| `suricata-eve.json` | Keluaran Suricata (`eve.json`, JSON per baris) | 18 aliran dari 198.51.100.23 ke 18 *port* Portal web → pemindaian *port*; HMI resmi 192.0.2.140 membaca register genset (bukan temuan); 192.0.2.183 menyeberang ke genset lalu menulis register pukul 14.02 menurut jam sensor → koneksi OT tanpa izin, tulis di luar jendela pemeliharaan, dan rantai IT ke OT |

Aturan yang menilai log impor sama persis dengan aturan latihan (`app/deteksi.py`). Waktu diputar ulang relatif: peristiwa terakhir di log dianggap terjadi saat ini, dan jarak antarperistiwa tetap. Hasilnya hanya menaikkan aset ke WASPADA; isolasi tetap keputusan Operator.

Wazuh dan Suricata dibaca dari berkas keluarannya saja: Nusantara Shield tidak memasang, mengatur, atau menghubungi sensor, dan tidak menjalankan *active response* atau IPS. Satu larik JSON hasil ekspor juga diterima. Jam perintah Modbus diambil dari stempel waktu sensor, jadi jendela pemeliharaan dinilai menurut jam di lokasi sensor.

Batas: ≈2 MB dan 50.000 baris per berkas. Nama akun dalam log tidak disimpan, dan isi log tidak masuk log audit (hanya nama berkas dan jumlah baris).
