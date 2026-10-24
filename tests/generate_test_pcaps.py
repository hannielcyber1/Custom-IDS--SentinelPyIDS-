"""
Script to generate reproducible test PCAP files for SentinelPy IDS.
Creates:
- tests/pcaps/benign.pcap
- tests/pcaps/icmp_sweep.pcap
- tests/pcaps/tcp_port_scan.pcap
- tests/pcaps/cleartext_creds.pcap
- tests/pcaps/ssh_burst.pcap
"""

import os
from scapy.all import IP, TCP, UDP, ICMP, Raw, wrpcap

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "pcaps")
os.makedirs(OUTPUT_DIR, exist_ok=True)

def generate_pcaps():
    # 1. Benign Traffic
    benign = [
        IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=54321, dport=53)/Raw(load=b"DNS-QUERY"),
        IP(src="192.168.1.100", dst="142.250.190.46")/TCP(sport=54322, dport=443, flags="S"),
        IP(src="192.168.1.100", dst="142.250.190.46")/TCP(sport=54322, dport=443, flags="A")
    ]
    wrpcap(os.path.join(OUTPUT_DIR, "benign.pcap"), benign)

    # 2. ICMP Ping Sweep (12 Echo Requests)
    icmp_sweep = []
    for _ in range(12):
        icmp_sweep.append(
            IP(src="10.0.0.50", dst="192.168.1.1")/ICMP(type=8, code=0)
        )
    wrpcap(os.path.join(OUTPUT_DIR, "icmp_sweep.pcap"), icmp_sweep)

    # 3. TCP Port Scan (20 unique ports on 192.168.1.10)
    port_scan = []
    for p in range(20, 40):
        port_scan.append(
            IP(src="10.0.0.77", dst="192.168.1.10")/TCP(sport=40000+p, dport=p, flags="S")
        )
    wrpcap(os.path.join(OUTPUT_DIR, "tcp_port_scan.pcap"), port_scan)

    # 4. Cleartext Credentials in HTTP
    creds_payload = b"POST /login.php HTTP/1.1\r\nHost: example.com\r\n\r\nuser=admin&pass=SuperSecret99"
    creds = [
        IP(src="192.168.1.15", dst="93.184.216.34")/TCP(sport=51234, dport=80, flags="PA")/Raw(load=creds_payload)
    ]
    wrpcap(os.path.join(OUTPUT_DIR, "cleartext_creds.pcap"), creds)

    # 5. SSH Burst (4 SYN packets to port 22)
    ssh_burst = []
    for i in range(4):
        ssh_burst.append(
            IP(src="10.0.0.99", dst="192.168.1.20")/TCP(sport=60000+i, dport=22, flags="S")
        )
    wrpcap(os.path.join(OUTPUT_DIR, "ssh_burst.pcap"), ssh_burst)

    # 6. DPI: SQL Injection via Regex
    sqli_payload = b"GET /products?id=1%20UNION%20SELECT%20username,%20password%20FROM%20users-- HTTP/1.1\r\nHost: target.local\r\n\r\n"
    sqli = [
        IP(src="192.168.1.88", dst="192.168.1.10")/TCP(sport=55111, dport=80, flags="PA")/Raw(load=sqli_payload)
    ]
    wrpcap(os.path.join(OUTPUT_DIR, "dpi_sqli.pcap"), sqli)

    # 7. DPI: Windows Executable (PE) File Download (Magic Bytes 'MZ')
    pe_payload = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\nMZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff"
    pe_exe = [
        IP(src="192.168.1.10", dst="192.168.1.88")/TCP(sport=80, dport=55111, flags="PA")/Raw(load=pe_payload)
    ]
    wrpcap(os.path.join(OUTPUT_DIR, "dpi_pe_exe.pcap"), pe_exe)

    # 8. DPI: TLS ClientHello with SNI extraction (Encrypted C2 Domain)
    host_bytes = b"evil-c2-server.com"
    sni_data = (
        (len(host_bytes) + 3).to_bytes(2, 'big') +
        b'\x00' +
        len(host_bytes).to_bytes(2, 'big') +
        host_bytes
    )
    ext_sni = b'\x00\x00' + len(sni_data).to_bytes(2, 'big') + sni_data
    extensions = ext_sni
    ext_len_bytes = len(extensions).to_bytes(2, 'big')
    handshake_body = b'\x03\x03' + (b'\xaa' * 32) + b'\x00' + b'\x00\x02\x00\x9c' + b'\x01\x00' + ext_len_bytes + extensions
    handshake = b'\x01' + len(handshake_body).to_bytes(3, 'big') + handshake_body
    tls_payload = b'\x16\x03\x01' + len(handshake).to_bytes(2, 'big') + handshake

    tls_pkt = [
        IP(src="192.168.1.88", dst="104.21.45.10")/TCP(sport=52000, dport=443, flags="PA")/Raw(load=tls_payload)
    ]
    wrpcap(os.path.join(OUTPUT_DIR, "dpi_tls_sni.pcap"), tls_pkt)

    print(f"[+] Successfully generated 8 test PCAP files in: {OUTPUT_DIR}")

if __name__ == "__main__":
    generate_pcaps()
