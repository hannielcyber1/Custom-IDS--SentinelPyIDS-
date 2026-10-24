"""
SentinelPy IDS - Behavioral Anomaly Detection Engine
Evaluates dynamic rolling window statistics for port scans, connection bursts, and flood attacks.
"""

import time
from collections import defaultdict
from typing import List, Dict, Set, Tuple, Any

from sentinelpy.rules.models import BehavioralRule
from sentinelpy.core.packet_record import PacketRecord
from sentinelpy.alerts.models import AlertEvent

class BehaviorEngine:
    def __init__(self, rules: List[BehavioralRule], sensor_id: str = "sentinelpy-lab"):
        self.rules = rules
        self.sensor_id = sensor_id
        
        # Internal state tracking:
        # (src_ip, dst_ip) -> list of (timestamp, dst_port)
        self._port_scan_history: Dict[Tuple[str, str], List[Tuple[float, int]]] = defaultdict(list)
        
        # src_ip -> list of timestamps for ICMP Echo
        self._icmp_history: Dict[str, List[float]] = defaultdict(list)
        
        # src_ip -> list of timestamps for ARP Requests
        self._arp_history: Dict[str, List[float]] = defaultdict(list)
        
        # (src_ip, dst_port) -> list of timestamps for connection attempts
        self._conn_burst_history: Dict[Tuple[str, int], List[float]] = defaultdict(list)

    def observe(self, record: PacketRecord) -> List[AlertEvent]:
        """Observes a normalized packet and evaluates all active behavioral rules."""
        alerts: List[AlertEvent] = []
        now = record.timestamp or time.time()

        for rule in self.rules:
            if not rule.enabled:
                continue

            detector = rule.detector
            window = rule.window_seconds
            cutoff = now - window

            # 1. Unique Destination Ports (TCP Port Scan Detector)
            if detector == "unique_destination_ports":
                if record.protocol == "tcp" and record.dst_port is not None:
                    key = (record.src_ip, record.dst_ip)
                    history = self._port_scan_history[key]
                    # Prune entries outside the time window
                    history = [(t, p) for (t, p) in history if t >= cutoff]
                    history.append((now, record.dst_port))
                    self._port_scan_history[key] = history

                    unique_ports = {p for (_, p) in history}
                    min_ports = rule.threshold.get("minimum_unique_ports", 15)
                    if len(unique_ports) >= min_ports:
                        alerts.append(AlertEvent(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            detection_type="behavioral",
                            severity=rule.severity,
                            src_ip=record.src_ip,
                            dst_ip=record.dst_ip,
                            protocol="tcp",
                            evidence={
                                "unique_destination_ports": len(unique_ports),
                                "window_seconds": window,
                                "sample_ports": sorted(list(unique_ports))[:10]
                            },
                            sensor=self.sensor_id
                        ))
                        # Reset window history after alert
                        self._port_scan_history[key] = []

            # 2. ICMP Echo Burst (Ping Sweep Detector)
            elif detector == "icmp_echo_burst":
                if record.protocol == "icmp" and record.icmp_type == 8:
                    history = self._icmp_history[record.src_ip]
                    history = [t for t in history if t >= cutoff]
                    history.append(now)
                    self._icmp_history[record.src_ip] = history

                    min_req = rule.threshold.get("minimum_requests", 10)
                    if len(history) >= min_req:
                        alerts.append(AlertEvent(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            detection_type="behavioral",
                            severity=rule.severity,
                            src_ip=record.src_ip,
                            dst_ip=record.dst_ip,
                            protocol="icmp",
                            evidence={
                                "icmp_echo_requests": len(history),
                                "window_seconds": window
                            },
                            sensor=self.sensor_id
                        ))
                        self._icmp_history[record.src_ip] = []

            # 3. ARP Request Burst (ARP Scan / Poisoning Detector)
            elif detector == "arp_request_burst":
                if record.protocol == "arp" and record.arp_op == 1:
                    history = self._arp_history[record.src_ip]
                    history = [t for t in history if t >= cutoff]
                    history.append(now)
                    self._arp_history[record.src_ip] = history

                    min_req = rule.threshold.get("minimum_requests", 60)
                    if len(history) >= min_req:
                        alerts.append(AlertEvent(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            detection_type="behavioral",
                            severity=rule.severity,
                            src_ip=record.src_ip,
                            dst_ip=record.dst_ip,
                            protocol="arp",
                            evidence={
                                "arp_requests": len(history),
                                "window_seconds": window
                            },
                            sensor=self.sensor_id
                        ))
                        self._arp_history[record.src_ip] = []

            # 4. Port Connection Burst (e.g. SSH Brute Force Detector)
            elif detector == "port_connection_burst":
                target_port = rule.scope.destination_port or 22
                if record.protocol == "tcp" and record.dst_port == target_port:
                    # Check for SYN flag (connection initiation)
                    if "S" in record.tcp_flags and "A" not in record.tcp_flags:
                        key = (record.src_ip, target_port)
                        history = self._conn_burst_history[key]
                        history = [t for t in history if t >= cutoff]
                        history.append(now)
                        self._conn_burst_history[key] = history

                        min_conn = rule.threshold.get("minimum_connections", 3)
                        if len(history) >= min_conn:
                            alerts.append(AlertEvent(
                                rule_id=rule.id,
                                rule_name=rule.name,
                                detection_type="behavioral",
                                severity=rule.severity,
                                src_ip=record.src_ip,
                                dst_ip=record.dst_ip,
                                protocol="tcp",
                                evidence={
                                    "target_port": target_port,
                                    "connection_attempts": len(history),
                                    "window_seconds": window
                                },
                                sensor=self.sensor_id
                            ))
                            self._conn_burst_history[key] = []

        return alerts
