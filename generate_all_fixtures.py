#!/usr/bin/env python3
"""
Synthetic PCAP Fixture Generator
================================
Generates deterministic, labeled synthetic PCAP files for testing, regression,
and demonstration of the C++17 Modular DPI & Packet Analyzer Platform.

Output Fixtures:
1. pcaps/normal_traffic.pcap      - Benign web browsing, DNS queries, clean TLS.
2. pcaps/port_scan_recon.pcap    - Horizontal & vertical port scans (Phase 3.1 & 3.3).
3. pcaps/dns_anomalies.pcap      - DNS tunneling, NXDOMAIN burst, query diversity.
4. pcaps/beacon_c2.pcap          - Periodic C2 beaconing connections.
5. pcaps/threat_intel_match.pcap - Traffic hitting known malicious IOCs & signatures.

Requires zero external dependencies (pure Python standard library).
"""

import struct
import socket
import os
import sys
import time

PCAP_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "pcaps"))

def checksum(msg):
    s = 0
    msg = (msg + b'\x00') if len(msg) % 2 else msg
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + msg[i+1]
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    return ~s & 0xffff

class PcapWriter:
    def __init__(self, filename):
        self.filename = filename
        self.f = open(filename, "wb")
        # Write PCAP Global Header (24 bytes)
        self.f.write(struct.pack("<IHHiIII",
            0xa1b2c3d4, # Magic
            2, 4,       # Version 2.4
            0,          # GMT to local correction
            0,          # Accuracy of timestamps
            65535,      # Snaplen
            1           # Data link type (Ethernet)
        ))

    def write_packet(self, data, ts_sec, ts_usec):
        length = len(data)
        header = struct.pack("<IIII", int(ts_sec), int(ts_usec), length, length)
        self.f.write(header)
        self.f.write(data)

    def close(self):
        self.f.close()

def build_eth(src_mac=b"\x00\x11\x22\x33\x44\x55", dst_mac=b"\x66\x77\x88\x99\xaa\xbb"):
    return dst_mac + src_mac + struct.pack("!H", 0x0800)

def build_ip(src_ip, dst_ip, proto, payload_len):
    total_len = 20 + payload_len
    ident = 54321
    flags_fo = 0x4000
    ttl = 64
    chk = 0
    src_b = socket.inet_aton(src_ip)
    dst_b = socket.inet_aton(dst_ip)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident, flags_fo, ttl, proto, chk, src_b, dst_b)
    chk = checksum(hdr)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident, flags_fo, ttl, proto, chk, src_b, dst_b)

def build_tcp(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload=b""):
    offset = 5 << 4
    win = 64240
    urg = 0
    hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, offset, flags, win, 0, urg)
    pseudo = struct.pack("!4s4sBBH", socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, 6, len(hdr) + len(payload))
    chk = checksum(pseudo + hdr + payload)
    hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, offset, flags, win, chk, urg)
    return hdr + payload

def build_udp(src_ip, dst_ip, src_port, dst_port, payload=b""):
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo = struct.pack("!4s4sBBH", socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, 17, length)
    chk = checksum(pseudo + hdr + payload)
    hdr = struct.pack("!HHHH", src_port, dst_port, length, chk)
    return hdr + payload

def build_dns_query(tx_id, domain):
    hdr = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0) # Standard query
    qname = b""
    for part in domain.split("."):
        qname += struct.pack("!B", len(part)) + part.encode("ascii")
    qname += b"\x00"
    qtail = struct.pack("!HH", 1, 1) # Type A, Class IN
    return hdr + qname + qtail

def build_dns_response(tx_id, domain, resolved_ip="93.184.216.34", rcode=0):
    flags = 0x8180 | (rcode & 0xF) # Response, Recursion Desired & Available
    hdr = struct.pack("!HHHHHH", tx_id, flags, 1, 1 if rcode == 0 else 0, 0, 0)
    qname = b""
    for part in domain.split("."):
        qname += struct.pack("!B", len(part)) + part.encode("ascii")
    qname += b"\x00"
    qtail = struct.pack("!HH", 1, 1) # Type A, Class IN
    
    ans = b""
    if rcode == 0:
        ans += b"\xc0\x0c" # Pointer to qname
        ans += struct.pack("!HHIH4s", 1, 1, 300, 4, socket.inet_aton(resolved_ip))
    return hdr + qname + qtail + ans

def build_tls_client_hello(server_name):
    sni_bytes = server_name.encode("utf-8")
    ext_sni = struct.pack("!HHHBH", 0x0000, len(sni_bytes) + 5, len(sni_bytes) + 3, 0x00, len(sni_bytes)) + sni_bytes
    ext_all = struct.pack("!H", len(ext_sni)) + ext_sni

    client_random = b"\x01" * 32
    session_id = b"\x00"
    cipher_suites = b"\x00\x02\xc0\x2f" # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    compression_methods = b"\x01\x00"

    ch_body = struct.pack("!H", 0x0303) + client_random + session_id + cipher_suites + compression_methods + ext_all
    handshake = struct.pack("!B", 0x01) + struct.pack("!I", len(ch_body))[1:] + ch_body
    tls_record = struct.pack("!BHH", 0x16, 0x0301, len(handshake)) + handshake
    return tls_record

def generate_normal_traffic(filename):
    writer = PcapWriter(filename)
    t = 1600000000.0

    # 1. Benign DNS query & response
    query_pkt = build_eth() + build_ip("192.168.1.100", "8.8.8.8", 17, 8 + len(build_dns_query(0x1234, "example.com"))) + build_udp("192.168.1.100", "8.8.8.8", 52140, 53, build_dns_query(0x1234, "example.com"))
    writer.write_packet(query_pkt, t, 1000)
    t += 0.02
    resp_pkt = build_eth() + build_ip("8.8.8.8", "192.168.1.100", 17, 8 + len(build_dns_response(0x1234, "example.com", "93.184.216.34"))) + build_udp("8.8.8.8", "192.168.1.100", 53, 52140, build_dns_response(0x1234, "example.com", "93.184.216.34"))
    writer.write_packet(resp_pkt, t, 1000)
    t += 0.05

    # 2. Benign HTTPS flow with TLS ClientHello
    tls_payload = build_tls_client_hello("example.com")
    # SYN
    syn = build_eth() + build_ip("192.168.1.100", "93.184.216.34", 6, 20) + build_tcp("192.168.1.100", "93.184.216.34", 49152, 443, 1000, 0, 0x02)
    writer.write_packet(syn, t, 2000)
    t += 0.01
    # SYN-ACK
    synack = build_eth() + build_ip("93.184.216.34", "192.168.1.100", 6, 20) + build_tcp("93.184.216.34", "192.168.1.100", 443, 49152, 5000, 1001, 0x12)
    writer.write_packet(synack, t, 3000)
    t += 0.01
    # ACK
    ack = build_eth() + build_ip("192.168.1.100", "93.184.216.34", 6, 20) + build_tcp("192.168.1.100", "93.184.216.34", 49152, 443, 1001, 5001, 0x10)
    writer.write_packet(ack, t, 4000)
    t += 0.01
    # Client Hello
    ch = build_eth() + build_ip("192.168.1.100", "93.184.216.34", 6, 20 + len(tls_payload)) + build_tcp("192.168.1.100", "93.184.216.34", 49152, 443, 1001, 5001, 0x18, tls_payload)
    writer.write_packet(ch, t, 5000)
    t += 0.02
    # FIN
    fin = build_eth() + build_ip("192.168.1.100", "93.184.216.34", 6, 20) + build_tcp("192.168.1.100", "93.184.216.34", 49152, 443, 1001 + len(tls_payload), 5001, 0x11)
    writer.write_packet(fin, t, 6000)

    writer.close()
    print(f"[Fixtures] Generated {filename}")

def generate_port_scan(filename):
    writer = PcapWriter(filename)
    t = 1600000000.0

    # 1. Vertical port scan (same target, multiple ports: 20 to 35)
    for p in range(20, 36):
        pkt = build_eth() + build_ip("192.168.1.200", "10.0.0.50", 6, 20) + build_tcp("192.168.1.200", "10.0.0.50", 40000 + p, p, 100, 0, 0x02)
        writer.write_packet(pkt, t, 1000)
        t += 0.005 # Rapid 5ms intervals

    # 2. Horizontal port scan (different targets, same port 445)
    for ip_last in range(1, 25):
        dst = f"10.0.0.{ip_last}"
        pkt = build_eth() + build_ip("192.168.1.200", dst, 6, 20) + build_tcp("192.168.1.200", dst, 50000 + ip_last, 445, 200, 0, 0x02)
        writer.write_packet(pkt, t, 1000)
        t += 0.005

    writer.close()
    print(f"[Fixtures] Generated {filename}")

def generate_dns_anomalies(filename):
    writer = PcapWriter(filename)
    t = 1600000000.0

    # 1. High frequency & DNS tunneling long subdomains
    for i in range(1, 25):
        tunnel_domain = f"v1a8f9c4d2e8b0a1c3e5_{i:04d}.exfil.data.tunneling-domain.com"
        dns_data = build_dns_query(0x2000 + i, tunnel_domain)
        pkt = build_eth() + build_ip("192.168.1.150", "8.8.8.8", 17, 8 + len(dns_data)) + build_udp("192.168.1.150", "8.8.8.8", 45000 + i, 53, dns_data)
        writer.write_packet(pkt, t, 1000)
        t += 0.01

        # Return NXDOMAIN for burst detection
        resp_data = build_dns_response(0x2000 + i, tunnel_domain, rcode=3) # NXDOMAIN
        resp = build_eth() + build_ip("8.8.8.8", "192.168.1.150", 17, 8 + len(resp_data)) + build_udp("8.8.8.8", "192.168.1.150", 53, 45000 + i, resp_data)
        writer.write_packet(resp, t, 2000)
        t += 0.01

    writer.close()
    print(f"[Fixtures] Generated {filename}")

def generate_beacon_c2(filename):
    writer = PcapWriter(filename)
    t = 1600000000.0

    # Periodic C2 beacon every 1.0 second with low jitter
    c2_ip = "198.51.100.44"
    for i in range(12):
        # SYN
        syn = build_eth() + build_ip("192.168.1.75", c2_ip, 6, 20) + build_tcp("192.168.1.75", c2_ip, 55000 + i, 8443, 100 + i, 0, 0x02)
        writer.write_packet(syn, t, 1000)
        # SYN-ACK
        synack = build_eth() + build_ip(c2_ip, "192.168.1.75", 6, 20) + build_tcp(c2_ip, "192.168.1.75", 8443, 55000 + i, 500 + i, 101 + i, 0x12)
        writer.write_packet(synack, t, 15000)
        # PSH-ACK Beacon payload (small check-in)
        beacon_data = b"HEARTBEAT_ID_0491_CHECKIN"
        psh = build_eth() + build_ip("192.168.1.75", c2_ip, 6, 20 + len(beacon_data)) + build_tcp("192.168.1.75", c2_ip, 55000 + i, 8443, 101 + i, 501 + i, 0x18, beacon_data)
        writer.write_packet(psh, t, 20000)
        # FIN
        fin = build_eth() + build_ip("192.168.1.75", c2_ip, 6, 20) + build_tcp("192.168.1.75", c2_ip, 101 + i + len(beacon_data), 8443, 101 + i, 501 + i, 0x11)
        writer.write_packet(fin, t, 30000)

        t += 1.002 # 1.002 seconds = strictly low-jitter periodic beacon

    writer.close()
    print(f"[Fixtures] Generated {filename}")

def generate_threat_intel_match(filename):
    writer = PcapWriter(filename)
    t = 1600000000.0

    # Traffic hitting known IOC from Phase 3.5 dataset (e.g. 93.184.216.34 and www.tiktok.com)
    # 1. Flow to 93.184.216.34
    syn = build_eth() + build_ip("192.168.1.100", "93.184.216.34", 6, 20) + build_tcp("192.168.1.100", "93.184.216.34", 48100, 80, 100, 0, 0x02)
    writer.write_packet(syn, t, 1000)
    t += 0.01

    http_req = b"GET /malware_payload.bin HTTP/1.1\r\nHost: 93.184.216.34\r\nUser-Agent: AttackBot/1.0\r\n\r\n"
    psh = build_eth() + build_ip("192.168.1.100", "93.184.216.34", 6, 20 + len(http_req)) + build_tcp("192.168.1.100", "93.184.216.34", 48100, 80, 101, 1, 0x18, http_req)
    writer.write_packet(psh, t, 2000)
    t += 0.05

    # 2. TLS handshake to www.tiktok.com (policy watchlist IOC)
    tls_payload = build_tls_client_hello("www.tiktok.com")
    ch = build_eth() + build_ip("192.168.1.100", "99.86.0.100", 6, 20 + len(tls_payload)) + build_tcp("192.168.1.100", "99.86.0.100", 48200, 443, 201, 1, 0x18, tls_payload)
    writer.write_packet(ch, t, 3000)

    writer.close()
    print(f"[Fixtures] Generated {filename}")

def main():
    os.makedirs(PCAP_DIR, exist_ok=True)
    print("===============================================================")
    print("      DPI & Packet Analyzer — Synthetic Fixture Generator     ")
    print("===============================================================")
    generate_normal_traffic(os.path.join(PCAP_DIR, "normal_traffic.pcap"))
    generate_port_scan(os.path.join(PCAP_DIR, "port_scan_recon.pcap"))
    generate_dns_anomalies(os.path.join(PCAP_DIR, "dns_anomalies.pcap"))
    generate_beacon_c2(os.path.join(PCAP_DIR, "beacon_c2.pcap"))
    generate_threat_intel_match(os.path.join(PCAP_DIR, "threat_intel_match.pcap"))
    print("===============================================================")
    print("ALL 5 SYNTHETIC PCAP FIXTURES GENERATED SUCCESSFULLY!")
    print("===============================================================\n")

if __name__ == "__main__":
    main()
