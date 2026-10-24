"""
SentinelPy IDS - Core Packet Normalization
Converts raw Scapy packets into clean, immutable, normalized PacketRecord instances.
"""

from dataclasses import dataclass, field
from typing import Optional
import time
from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, Raw

from sentinelpy.enrichment.ja3 import compute_ja3
from sentinelpy.enrichment.http_parser import parse_http

_HTTP_DST_PORTS = {80, 8080, 8000, 8888, 3000}
_HTTP_SRC_PORTS = {80, 8080, 8000}

@dataclass(slots=True, frozen=True)
class PacketRecord:
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: str = ""
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    arp_op: Optional[int] = None
    arp_psrc: Optional[str] = None
    arp_pdst: Optional[str] = None
    packet_length: int = 0
    payload_bytes: bytes = b""
    payload_text: str = ""
    tls_sni: Optional[str] = None
    # --- JA3 TLS fingerprint ---
    ja3: Optional[str] = None
    # --- HTTP parsed fields ---
    http_method: Optional[str] = None
    http_uri: Optional[str] = None
    http_host: Optional[str] = None
    http_user_agent: Optional[str] = None
    # --- GeoIP enrichment (populated by engine) ---
    src_country: Optional[str] = None
    dst_country: Optional[str] = None
    src_isp: Optional[str] = None

    @property
    def flow_key(self) -> str:
        """Returns a canonical bidirectional 5-tuple flow key."""
        endpoints = sorted([
            (self.src_ip, self.src_port or 0),
            (self.dst_ip, self.dst_port or 0)
        ])
        return f"{self.protocol}:{endpoints[0][0]}:{endpoints[0][1]}<->{endpoints[1][0]}:{endpoints[1][1]}"

def extract_tls_sni(payload: bytes) -> Optional[str]:
    """
    Inspects TLS ClientHello handshake packet to extract Server Name Indication (SNI).
    Safely returns None if not TLS or SNI is not present.
    """
    try:
        # TLS record header: byte 0=0x16 (Handshake), byte 5=0x01 (ClientHello)
        if len(payload) < 44 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        offset = 43
        session_id_len = payload[offset]
        offset += 1 + session_id_len
        if offset + 2 > len(payload):
            return None
        cipher_len = int.from_bytes(payload[offset:offset+2], "big")
        offset += 2 + cipher_len
        if offset + 1 > len(payload):
            return None
        comp_len = payload[offset]
        offset += 1 + comp_len
        if offset + 2 > len(payload):
            return None
        ext_len = int.from_bytes(payload[offset:offset+2], "big")
        offset += 2
        end_ext = min(len(payload), offset + ext_len)

        while offset + 4 <= end_ext:
            ext_type = int.from_bytes(payload[offset:offset+2], "big")
            ext_data_len = int.from_bytes(payload[offset+2:offset+4], "big")
            offset += 4
            if ext_type == 0x0000: # SNI Extension
                if offset + 5 <= len(payload):
                    # SNI list length (2B), type (1B), name length (2B)
                    name_len = int.from_bytes(payload[offset+3:offset+5], "big")
                    name_bytes = payload[offset+5:offset+5+name_len]
                    return name_bytes.decode("utf-8", errors="ignore").lower()
            offset += ext_data_len
    except Exception:
        return None
    return None

def normalize_packet(packet) -> Optional[PacketRecord]:
    """
    Safely inspects a raw Scapy packet and extracts normalized fields.
    Returns None if packet is malformed or unsupported.
    """
    try:
        pkt_time = float(getattr(packet, "time", time.time()))
        pkt_len = len(packet)
        
        # 1. Handle ARP
        if packet.haslayer(ARP):
            arp = packet[ARP]
            return PacketRecord(
                timestamp=pkt_time,
                src_ip=str(arp.psrc),
                dst_ip=str(arp.pdst),
                protocol="arp",
                arp_op=int(arp.op),
                arp_psrc=str(arp.psrc),
                arp_pdst=str(arp.pdst),
                packet_length=pkt_len
            )
        
        # 2. Handle IPv4 / IPv6
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        if packet.haslayer(IP):
            src_ip = str(packet[IP].src)
            dst_ip = str(packet[IP].dst)
        elif packet.haslayer(IPv6):
            src_ip = str(packet[IPv6].src)
            dst_ip = str(packet[IPv6].dst)
        else:
            return None # Skip non-IP and non-ARP packets

        # Protocol & Port extraction
        protocol = "ip"
        src_port = None
        dst_port = None
        tcp_flags = ""
        icmp_type = None
        icmp_code = None
        payload_bytes = b""
        payload_text = ""

        ja3_hash = None
        http_method = None
        http_uri = None
        http_host = None
        http_user_agent = None

        if packet.haslayer(TCP):
            protocol = "tcp"
            tcp = packet[TCP]
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            tcp_flags = str(tcp.flags)
        elif packet.haslayer(UDP):
            protocol = "udp"
            udp = packet[UDP]
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
        elif packet.haslayer(ICMP):
            protocol = "icmp"
            icmp = packet[ICMP]
            icmp_type = int(icmp.type)
            icmp_code = int(icmp.code)

        # Extract Raw Payload if available
        tls_sni = None
        if packet.haslayer(Raw):
            try:
                payload_bytes = bytes(packet[Raw].load)
                payload_text = payload_bytes.decode(errors="ignore")
                tls_sni = extract_tls_sni(payload_bytes)
                # JA3 fingerprint from TLS ClientHello
                ja3_hash = compute_ja3(payload_bytes)
                # HTTP parser for common web ports
                if protocol == "tcp" and (
                    dst_port in _HTTP_DST_PORTS or src_port in _HTTP_SRC_PORTS
                ):
                    http_info = parse_http(payload_bytes)
                    if http_info:
                        http_method = http_info.get("method")
                        http_uri = http_info.get("uri")
                        http_host = http_info.get("host")
                        http_user_agent = http_info.get("user_agent")
            except Exception:
                payload_bytes = b""
                payload_text = ""
                tls_sni = None

        return PacketRecord(
            timestamp=pkt_time,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            tcp_flags=tcp_flags,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            packet_length=pkt_len,
            payload_bytes=payload_bytes,
            payload_text=payload_text,
            tls_sni=tls_sni,
            ja3=ja3_hash,
            http_method=http_method,
            http_uri=http_uri,
            http_host=http_host,
            http_user_agent=http_user_agent,
        )

    except Exception:
        return None
