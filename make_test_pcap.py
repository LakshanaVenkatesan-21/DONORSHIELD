import struct, socket

f = open('test_snort.pcap', 'wb')
# Global header: magic, version 2.4, snaplen 65535, linktype 1 (Ethernet)
f.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

src = socket.inet_aton('10.0.0.5')
dst = socket.inet_aton('192.168.1.1')

for i, port in enumerate(range(1, 20)):
    eth = b'\xff\xff\xff\xff\xff\xff' + b'\x00\x11\x22\x33\x44\x55' + b'\x08\x00'
    ip  = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, i, 0, 64, 6, 0, src, dst)
    tcp = struct.pack('!HHIIBBHHH', 12345, port, 0, 0, 0x50, 0x02, 1024, 0, 0)
    frame = eth + ip + tcp
    f.write(struct.pack('<IIII', i, 0, len(frame), len(frame)))
    f.write(frame)

f.close()
print(f'wrote test_snort.pcap ({19} SYN packets to ports 1-19)')
