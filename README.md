# DHCP Test Script

## Deskripsi

Program ini berfungsi untuk menguji server DHCP.
Program ini melakukan pengiriman permintaan DHCP (seperti `discover` dan `request`), menerima balasan dari server, dan kemudian merilis alamat IP yang telah disewa. Program ini dapat digunakan untuk memastikan bahwa server DHCP berfungsi dengan benar dalam mengalokasikan alamat IP kepada klien.

## Fitur

- **Pembuatan Alamat MAC Acak:** Script ini secara otomatis menghasilkan alamat MAC acak untuk setiap pengujian.
- **Pembuatan dan Pengiriman Paket DHCP:** Script ini menyiapkan dan mengirim paket DHCP (discover, request, release) ke server DHCP.
- **Pemantauan Balasan:** Script ini memantau balasan dari server DHCP untuk memastikan bahwa alamat IP diberikan dengan benar.
- **Pengulangan Pengujian:** Script ini dapat diatur untuk mengulangi pengujian beberapa kali untuk validasi lebih lanjut.
- **Pelepasan IP:** Setelah pengujian selesai, script akan melepaskan semua alamat IP yang telah disewa.

## Persyaratan

- Python 2.x
- Modul Python:
  - `random`
  - `optparse`
  - `pydhcplib`
  - `socket`
  - `sys`
  - `time`
  - `pcap`
  - `struct`

## Penggunaan

```bash
python dhcp_test.py [IP server DHCP] [Port server DHCP - Opsional default ke 67] [Jumlah Loop - Opsional default ke 1]
```

### Contoh:

```bash
python dhcp_test.py 192.168.1.1
```

### Argumen:

- `DHCP server IP`: Alamat IP server DHCP yang ingin diuji.
- `DHCP server port`: (Opsional) Port server DHCP, defaultnya adalah 67.
- `Number of Loops`: (Opsional) Jumlah pengulangan pengujian, defaultnya adalah 1.

## Catatan 

Skrip Ini Dibuat Untuk Tujuan Pendidikan Dan Penelitian Secara Etis.
Jika DI gunakana untuk Kegiatan Ilegal , Maka Saya Tidak Bertanggung Jawab Atas Penyalahgunaan Skrip Ini!

## Lisensi

