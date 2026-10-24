"""
SentinelPy IDS - Live Network Capture Adapter
Sniffs real-time traffic from authorized network interfaces using Scapy.
"""

from typing import Callable, Optional
from scapy.all import sniff, get_if_list
from sentinelpy.monitoring.metrics import MetricsCollector

class LiveCapture:
    def __init__(self, interface: Optional[str], metrics: MetricsCollector):
        self.interface = interface
        self.metrics = metrics

    def start(self, packet_handler: Callable[[object], None]):
        """Starts live packet capture on the selected or default interface."""
        kwargs = {"prn": packet_handler, "store": False}
        if self.interface:
            kwargs["iface"] = self.interface

        sniff(**kwargs)

    @staticmethod
    def get_interfaces():
        """Returns the list of detected network interfaces."""
        try:
            return get_if_list()
        except Exception:
            return []
