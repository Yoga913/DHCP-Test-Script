#!/usr/bin/env python
'''
Skrip akan melakukan uji beban pada server DHCP dengan terus-menerus meminta sewa alamat dalam satu putaran menggunakan alamat mac yang dibuat secara acak. 
Ini akan berjalan secara serial seperti yang tertulis, jika Anda ingin menjalankan beberapa skrip, Anda harus menjalankannya dalam beberapa proses.
Ketahuilah bahwa jika Anda menjalankannya dalam beberapa proses, Anda mungkin mengalami sejumlah kegagalan sewa pada klien DHCP Anda karena beberapa paket penemuan masuk sebelum permintaan masuk sehingga beberapa permintaan untuk alamat yang sama dapat terjadi. 
Ini adalah perilaku normal karena dalam pengaturan nyata klien akan mencoba lagi beberapa kali jika hal ini terjadi.

 (satu hal yang *MUNGKIN* perlu Anda lakukan adalah menetapkan promiscuous untuk objek pcap -> panggilan open_live)

Ini sama sekali bukan uji DHCP yang komprehensif, hanya skrip kecil sekali untuk memeriksa bahwa server mampu menangani angka beban.

-Beberapa catatan yang cukup sederhana tetapi terkadang terlupakan:

*Pastikan server DHCP Anda dapat dijangkau melalui IP-nya (klien yang menjalankan skrip dapat melihat subnet tempatnya berada)

*Pastikan server DHCP Anda tidak mencoba menyewakan IP-nya sendiri (dengan kata lain jangan tetapkan IP untuk pengujian dalam rentang sewa)

Penggunaan: dhcp_test.py [IP server DHCP] [Port server DHCP - Opsional default ke 67] [Jumlah Loop - Opsional default ke 1]
'''
from random import Random
from optparse import OptionParser
from pydhcplib.dhcp_packet import DhcpPacket
from pydhcplib.dhcp_network import DhcpClient
from pydhcplib.type_hw_addr import hwmac
from pydhcplib.type_ipv4 import ipv4
import socket
import sys
import time
import pcap
import struct

r = Random()
r.seed()

break_wait = 0
res = None

dhcp_ip = ''

# menghasilkan alamat MAC acak
def genmac():
        i = []
        for z in range(6):
                i.append(r.randint(0,255))
        return ':'.join(map(lambda x: "%02x"%x,i))

# menghasilkan XID acak
def genxid():
        decxid = r.randint(0,0xffffffff)
        xid = []
        for i in range(4):
                xid.insert(0, decxid & 0xff)
                decxid = decxid >> 8
        return xid

# mendapatkan paket data
def get_packet(pktlen, data, timestamp):
        global dhcp_ip
        global break_wait
        global res
        if not data:
                return
        if data[12:14] == '\x08\x00':
                decoded = decode_ip_packet(data[14:])
                if decoded['source_address'] == dhcp_ip:
                        res = decoded['destination_address'] # memanfaatkan CNR menggunakan alamat IP baru sebagai alamat tujuan...
                        break_wait = 1

# mengirim permintaan ke server
def issueRequest(serverip, serverport, timeout, req):
        global break_wait
        global res

        # Reset variabel global yang akan digunakan di sini
        break_wait = 0
        res = None
        client = DhcpClient(client_listen_port=67, server_listen_port=serverport)
        client.dhcp_socket.settimeout(timeout)
        if serverip == '0.0.0.0':
                req.SetOption('flags',[128, 0])
        req_type = req.GetOption('dhcp_message_type')[0]

        pcap_obj = pcap.pcapObject()
        dev = pcap.lookupdev()
        pcap_obj.open_live(dev, 1600, 0, 100)
        pcap_obj.setfilter("udp port 67", 0, 0)
        sent = 0
        while break_wait < 1:
                if(sent < 1):
                        sent = 1
                        client.SendDhcpPacketTo(req,serverip,serverport)
                if req_type == 3 or req_type == 7:
                        return
                pcap_obj.dispatch(1, get_packet)

        return res

# menyusun paket DHCP, default ke tipe "discover"
def preparePacket(xid=None, giaddr='0.0.0.0', chaddr='00:00:00:00:00:00', ciaddr='0.0.0.0', yiaddr='0.0.0.0', msgtype='discover', required_opts=[]):
        req = DhcpPacket()
        req.SetOption('op',[1])
        req.SetOption('htype',[1])
        req.SetOption('hlen',[6])
        req.SetOption('hops',[0])
        if not xid:
                xid = genxid()
        req.SetOption('xid',xid)
        req.SetOption('giaddr',ipv4(giaddr).list())
        req.SetOption('chaddr',hwmac(chaddr).list() + [0] * 10)
        req.SetOption('ciaddr',ipv4(ciaddr).list())
        if msgtype == 'request':
                mt = 3
        elif msgtype == 'release':
                mt = 7
        else:
                mt = 1
        if mt == 3:
                req.SetOption('yiaddr', ipv4(yiaddr).list())
                req.SetOption('request_ip_address', ipv4(yiaddr).list())
        req.SetOption('dhcp_message_type',[mt])
        return req

# mendekode paket untuk mendapatkan informasi seperti alamat sumber guna memverifikasi apakah balasan datang dari tempat yang diharapkan
def decode_ip_packet(s):
    d = {}
    d['version'] = (ord(s[0]) & 0xf0) >> 4
    d['header_len'] = ord(s[0]) & 0x0f
    d['tos'] = ord(s[1])
    d['total_len'] = socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['id'] = socket.ntohs(struct.unpack('H',s[4:6])[0])
    d['flags'] = (ord(s[6]) & 0xe0) >> 5
    d['fragment_offset'] = socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
    d['ttl'] = ord(s[8])
    d['protocol'] = ord(s[9])
    d['checksum'] = socket.ntohs(struct.unpack('H',s[10:12])[0])
    d['source_address'] = pcap.ntoa(struct.unpack('i',s[12:16])[0])
    d['destination_address'] = pcap.ntoa(struct.unpack('i',s[16:20])[0])
    if d['header_len'] > 5:
        d['options'] = s[20:4*(d['header_len']-5)]
    else:
        d['options'] = None
    d['data'] = s[4*d['header_len']:]
    return d

# awal bagian global, ini adalah titik masuk "main"
dhcp_ip = "0.0.0.0"
dhcp_port = 67
loops = 1
if len(sys.argv) != 3 and len(sys.argv) != 4 and len(sys.argv) != 5:
    print ("Penggunaan: dhcp_test.py [IP server DHCP] [Port server DHCP - Default opsional ke 67] [Jumlah Loop - Default opsional ke 1]")
    sys.exit(0)
elif len(sys.argv) != 4 and len(sys.argv) != 5:
    loops = 1
    dhcp_port = 67
    dhcp_ip = sys.argv[1]
elif len(sys.argv) != 5:
    loops = 1
    dhcp_ip = sys.argv[1]
    dhcp_port = int(sys.argv[2])
else:
    loops = int(sys.argv[3])
    dhcp_port = int(sys.argv[2])
    dhcp_ip = sys.argv[1]
    
leases = {}
run_loops = loops
# menjalankan ini sebanyak yang diperlukan untuk menguji server Anda
while run_loops > 0:
    # mendapatkan alamat MAC
    mac = genmac()
    
    # membuat paket penemuan
    disc_packet = preparePacket(None, '0.0.0.0', mac, '0.0.0.0', '0.0.0.0', 'discover', [1,3,6,51])
    
    # mengirim permintaan penemuan ke server
    ip_issued = issueRequest(dhcp_ip, dhcp_port, 4, disc_packet)
    
    # menggunakan IP yang ditemukan untuk membuat paket permintaan
    req_packet = preparePacket(None, '0.0.0.0', mac, '0.0.0.0', ip_issued, 'request', [1,3,6,51])
    
    # mengirimkan permintaan sewa sebenarnya
    res = issueRequest(dhcp_ip, dhcp_port, 4, req_packet)
    
    # mencetak jika kita mendapatkan balasan sewa yang buruk
    if ip_issued == '255.255.255.255':
        print (mac)
        print (ip_issued)
        print ("error getting lease")
    else:
        leases[ip_issued] = mac
    run_loops = run_loops - 1

# jeda sebelum kita melepaskan semua alamat untuk dilihat di server DHCP
entered = raw_input("Tekan tombol 'Enter' untuk melanjutkan...")

# loop melalui semua sewa kita dan beri tahu server DHCP bahwa kita selesai dengan mereka 
for k, v in leases.items():
    rel_packet = preparePacket(None, '0.0.0.0', v, k, '0.0.0.0', 'release', [1,3,6,51])
    ip_issued = issueRequest(dhcp_ip, dhcp_port, 4, rel_packet)


### Penjelasan Alur Kode Program:
# 1. **Import Module:**
#    - Kode ini mengimpor beberapa modul penting untuk mengelola paket DHCP, menangani alamat IP dan MAC, serta menangani socket jaringan.

# 2. **Inisialisasi Variabel:**
#    - Variabel global `break_wait`, `res`, dan `dhcp_ip` digunakan untuk melacak status program.

# 3. **Fungsi `genmac`:**
#    - Menghasilkan alamat MAC acak yang akan digunakan dalam paket DHCP.

# 4. **Fungsi `genxid`:**
#    - Menghasilkan ID transaksi (XID) acak yang diperlukan untuk mengidentifikasi transaksi DHCP.

# 5. **Fungsi `get_packet`:**
#    - Mengambil paket jaringan yang diterima dan memeriksa apakah paket tersebut berasal dari server DHCP yang diharapkan.

# 6. **Fungsi `issueRequest`:**
#    - Mengirim permintaan DHCP ke server dan menangani balasan menggunakan pemantauan paket secara langsung (live capture).

# 7. **Fungsi `preparePacket`:**
#    - Menyiapkan paket DHCP dengan tipe yang sesuai (discover, request, atau release) dan mengisi opsi yang diperlukan.

# 8. **Fungsi `decode_ip_packet`:**
#    - Mendekode paket IP untuk mendapatkan informasi seperti alamat sumber dan tujuan, yang digunakan untuk memverifikasi keaslian balasan DHCP.

# 9. **Alur Utama Program:**
#    - Program ini memulai dengan membaca argumen baris perintah untuk menentukan IP server DHCP, port, dan jumlah pengulangan tes.
#    - Program kemudian menghasilkan alamat MAC acak, membuat paket penemuan DHCP, mengirimnya ke server, dan menunggu balasan.
#    - Setelah menerima balasan, program membuat dan mengirim paket permintaan DHCP untuk mendapatkan sewa IP.
#    - Program akan mencetak kesalahan jika balasan tidak sesuai dan akan menyimpan sewa IP yang berhasil ke dalam dictionary.
#    - Setelah semua tes selesai, program menunggu input pengguna sebelum melepaskan semua alamat IP yang disewa.
