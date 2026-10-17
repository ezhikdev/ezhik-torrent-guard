#!/usr/bin/env python3
"""Write a pcap with a complete BitTorrent peer-wire TCP session.

usage: make_bt_pcap.py OUT.pcap LOCAL_IP LOCAL_PORT PEER_IP PEER_PORT [--http]
--http writes an ordinary HTTP session instead (negative control).
"""
import os
import struct
import sys
import time


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ip_bytes(ip):
    return bytes(int(x) for x in ip.split("."))


def packet(src, sport, dst, dport, seq, ack, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    pseudo = ip_bytes(src) + ip_bytes(dst) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, ip_bytes(src), ip_bytes(dst))
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
    return eth + ip + tcp


def session(local, lport, peer, pport, http=False):
    SYN, ACK, PSH = 0x02, 0x10, 0x08
    c_seq, s_seq = 1000, 5000
    pkts = [packet(local, lport, peer, pport, c_seq, 0, SYN),
            packet(peer, pport, local, lport, s_seq, c_seq + 1, SYN | ACK),
            packet(local, lport, peer, pport, c_seq + 1, s_seq + 1, ACK)]
    c_seq += 1
    s_seq += 1
    if http:
        c_msgs = [b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n\r\n"]
        s_msgs = [b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"]
    else:
        info_hash, peer_id = os.urandom(20), b"-qB4650-" + os.urandom(12)
        handshake = b"\x13BitTorrent protocol" + b"\x00\x00\x00\x00\x00\x10\x00\x05" + info_hash
        c_msgs = [handshake + peer_id, struct.pack("!IB", 1, 2), struct.pack("!IBIII", 13, 6, 0, 0, 16384)]
        s_msgs = [handshake + b"-TR4060-" + os.urandom(12), struct.pack("!IB", 1, 1),
                  struct.pack("!IB", 5, 5) + b"\xff\xff\xff\xff"]
    for c, s in zip(c_msgs, s_msgs):
        pkts.append(packet(local, lport, peer, pport, c_seq, s_seq, PSH | ACK, c))
        c_seq += len(c)
        pkts.append(packet(peer, pport, local, lport, s_seq, c_seq, PSH | ACK, s))
        s_seq += len(s)
    return pkts


def main():
    out, local, lport, peer, pport = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], int(sys.argv[5])
    pkts = session(local, lport, peer, pport, http="--http" in sys.argv)
    now = time.time()
    with open(out, "wb") as handle:
        handle.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, pkt in enumerate(pkts):
            ts = now + i * 0.01
            handle.write(struct.pack("!IIII", int(ts), int((ts % 1) * 1e6), len(pkt), len(pkt)) + pkt)
    print(f"wrote {len(pkts)} packets to {out}")


if __name__ == "__main__":
    main()
