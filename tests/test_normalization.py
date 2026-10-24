import pytest
from scapy.all import IP, TCP, ICMP, Raw
from sentinelpy.core.packet_record import normalize_packet, PacketRecord
from sentinelpy.core.flow_tracker import FlowTracker

def test_normalize_tcp_packet():
    pkt = IP(src="192.168.1.10", dst="192.168.1.20")/TCP(sport=12345, dport=80, flags="S")
    rec = normalize_packet(pkt)
    assert rec is not None
    assert rec.src_ip == "192.168.1.10"
    assert rec.dst_ip == "192.168.1.20"
    assert rec.protocol == "tcp"
    assert rec.src_port == 12345
    assert rec.dst_port == 80
    assert "S" in rec.tcp_flags

def test_normalize_payload_extraction():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=5000, dport=80)/Raw(load=b"password=admin123")
    rec = normalize_packet(pkt)
    assert rec is not None
    assert "password=admin123" in rec.payload_text

def test_flow_tracker_bidirectional():
    tracker = FlowTracker(idle_timeout=60.0)
    pkt_fwd = IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=5000, dport=80, flags="S")
    pkt_rev = IP(src="10.0.0.2", dst="10.0.0.1")/TCP(sport=80, dport=5000, flags="SA")

    rec1 = normalize_packet(pkt_fwd)
    rec2 = normalize_packet(pkt_rev)

    flow1 = tracker.update(rec1)
    flow2 = tracker.update(rec2)

    # Must map to the exact same bidirectional flow
    assert flow1.flow_key == flow2.flow_key
    assert tracker.active_flows_count() == 1
    assert flow2.packets_forward == 1
    assert flow2.packets_reverse == 1
    assert flow2.total_packets == 2
