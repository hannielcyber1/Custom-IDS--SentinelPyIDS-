"""
SentinelPy IDS - PCAP Replay Capture Adapter
Enables deterministic offline packet replay for reproducible testing and rule validation.
"""

import time
from typing import Callable, Optional
from scapy.all import rdpcap, PcapReader
from sentinelpy.core.packet_record import normalize_packet
from sentinelpy.monitoring.metrics import MetricsCollector

class PcapReplayer:
    def __init__(self, pcap_path: str, metrics: MetricsCollector):
        self.pcap_path = pcap_path
        self.metrics = metrics

    def replay(self, packet_handler: Callable[[object], None], max_packets: Optional[int] = None) -> int:
        """
        Streams packets from the PCAP file through the packet handler.
        Uses PcapReader for memory-efficient iteration on large captures.
        """
        count = 0
        with PcapReader(self.pcap_path) as reader:
            for pkt in reader:
                count += 1
                packet_handler(pkt)
                if max_packets and count >= max_packets:
                    break
        return count
