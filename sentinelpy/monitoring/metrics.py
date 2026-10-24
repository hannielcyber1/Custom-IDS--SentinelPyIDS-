"""
SentinelPy IDS - Performance & Health Monitoring
Tracks packet counters, throughput, latency, and operational health metrics.
"""

import time
import threading
from typing import Dict, Any

class MetricsCollector:
    def __init__(self):
        self.start_time = time.time()
        self.packets_captured = 0
        self.packets_processed = 0
        self.bytes_processed = 0
        self.alerts_generated = 0
        self.invalid_or_unsupported = 0
        self.total_detection_latency = 0.0
        self._lock = threading.Lock()

    def record_packet(self, byte_length: int, valid: bool, latency: float = 0.0):
        with self._lock:
            self.packets_captured += 1
            if valid:
                self.packets_processed += 1
                self.bytes_processed += byte_length
                self.total_detection_latency += latency
            else:
                self.invalid_or_unsupported += 1

    def record_alert(self):
        with self._lock:
            self.alerts_generated += 1

    def get_summary(self, active_flows: int = 0) -> Dict[str, Any]:
        with self._lock:
            uptime = max(0.001, time.time() - self.start_time)
            pps = self.packets_processed / uptime
            mbps = (self.bytes_processed * 8) / (uptime * 1_000_000)
            avg_lat_ms = (
                (self.total_detection_latency / self.packets_processed) * 1000
                if self.packets_processed > 0 else 0.0
            )

            return {
                "uptime_seconds": round(uptime, 2),
                "packets_captured": self.packets_captured,
                "packets_processed": self.packets_processed,
                "bytes_processed": self.bytes_processed,
                "invalid_packets": self.invalid_or_unsupported,
                "alerts_generated": self.alerts_generated,
                "active_flows": active_flows,
                "packets_per_second": round(pps, 2),
                "throughput_mbps": round(mbps, 4),
                "avg_detection_latency_ms": round(avg_lat_ms, 4)
            }
