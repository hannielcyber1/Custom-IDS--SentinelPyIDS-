import pytest
from scapy.all import IP, TCP, ICMP, Raw
from sentinelpy.core.packet_record import normalize_packet
from sentinelpy.rules.models import SignatureRule, SignatureMatch, BehavioralRule, BehavioralScope
from sentinelpy.detection.signature_engine import SignatureEngine
from sentinelpy.detection.behavior_engine import BehaviorEngine

def test_signature_engine_match_ssh():
    engine = SignatureEngine()
    rule = SignatureRule(
        id="TEST-SSH",
        name="SSH SYN",
        severity="informational",
        match=SignatureMatch(protocol="tcp", destination_port=22, tcp_flags="S")
    )

    pkt_ssh = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=54321, dport=22, flags="S")
    pkt_http = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=54321, dport=80, flags="S")

    rec_ssh = normalize_packet(pkt_ssh)
    rec_http = normalize_packet(pkt_http)

    assert engine.matches(rule, rec_ssh) is True
    assert engine.matches(rule, rec_http) is False

def test_behavior_engine_port_scan():
    rule = BehavioralRule(
        id="TEST-SCAN",
        name="Port Scan Test",
        detector="unique_destination_ports",
        scope=BehavioralScope(protocol="tcp"),
        window_seconds=10,
        threshold={"minimum_unique_ports": 5}
    )
    engine = BehaviorEngine([rule])

    # Send packets to 4 unique ports (below threshold)
    alerts = []
    for port in [80, 443, 22, 21]:
        pkt = IP(src="192.168.1.50", dst="192.168.1.1")/TCP(sport=30000+port, dport=port, flags="S")
        rec = normalize_packet(pkt)
        alerts.extend(engine.observe(rec))

    assert len(alerts) == 0

    # 5th port should trigger the alert!
    pkt_5 = IP(src="192.168.1.50", dst="192.168.1.1")/TCP(sport=30053, dport=53, flags="S")
    alerts_triggered = engine.observe(normalize_packet(pkt_5))
    assert len(alerts_triggered) == 1
    assert alerts_triggered[0].rule_id == "TEST-SCAN"
    assert alerts_triggered[0].evidence["unique_destination_ports"] == 5

def test_dpi_regex_match():
    engine = SignatureEngine()
    rule = SignatureRule(
        id="DPI-SQLI",
        name="SQL Injection",
        match=SignatureMatch(
            protocol="tcp",
            destination_port=80,
            regex="(?i)(union\\s+select|select.*from)"
        )
    )

    malicious_pkt = IP(src="1.1.1.1", dst="2.2.2.2")/TCP(sport=1000, dport=80)/Raw(load=b"GET /items?id=1 UNION SELECT name, pass FROM users")
    benign_pkt = IP(src="1.1.1.1", dst="2.2.2.2")/TCP(sport=1000, dport=80)/Raw(load=b"GET /items?id=1 HTTP/1.1")

    assert engine.matches(rule, normalize_packet(malicious_pkt)) is True
    assert engine.matches(rule, normalize_packet(benign_pkt)) is False

def test_dpi_magic_bytes_match():
    engine = SignatureEngine()
    rule = SignatureRule(
        id="DPI-PE",
        name="PE Executable",
        match=SignatureMatch(
            protocol="tcp",
            ports=[80],
            magic_bytes="4D5A" # 'MZ'
        )
    )

    exe_pkt = IP(src="1.1.1.1", dst="2.2.2.2")/TCP(sport=80, dport=5000)/Raw(load=b"HTTP/1.1 200 OK\r\n\r\nMZ\x90\x00")
    txt_pkt = IP(src="1.1.1.1", dst="2.2.2.2")/TCP(sport=80, dport=5000)/Raw(load=b"HTTP/1.1 200 OK\r\n\r\nHello World")

    assert engine.matches(rule, normalize_packet(exe_pkt)) is True
    assert engine.matches(rule, normalize_packet(txt_pkt)) is False

def test_dpi_tls_sni_match():
    from sentinelpy.core.packet_record import extract_tls_sni
    host = b"target-c2.net"
    sni_data = (len(host) + 3).to_bytes(2, 'big') + b'\x00' + len(host).to_bytes(2, 'big') + host
    ext = b'\x00\x00' + len(sni_data).to_bytes(2, 'big') + sni_data
    body = b'\x03\x03' + (b'\xaa' * 32) + b'\x00' + b'\x00\x02\x00\x9c' + b'\x01\x00' + len(ext).to_bytes(2, 'big') + ext
    handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
    tls_bytes = b'\x16\x03\x01' + len(handshake).to_bytes(2, 'big') + handshake

    assert extract_tls_sni(tls_bytes) == "target-c2.net"

    pkt = IP(src="1.1.1.1", dst="2.2.2.2")/TCP(sport=5000, dport=443)/Raw(load=tls_bytes)
    rec = normalize_packet(pkt)
    assert rec.tls_sni == "target-c2.net"

    engine = SignatureEngine()
    rule = SignatureRule(
        id="DPI-SNI",
        name="C2 SNI",
        match=SignatureMatch(
            protocol="tcp",
            destination_port=443,
            tls_sni="target-c2.net"
        )
    )
    assert engine.matches(rule, rec) is True

