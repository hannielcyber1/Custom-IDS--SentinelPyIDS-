"""
SentinelPy IDS - Core Flow Tracker
Maintains bidirectional flow states, counters, and manages flow expiration with memory limits.
"""

from dataclasses import dataclass, field
import time
from typing import Dict, List, Optional
from sentinelpy.core.packet_record import PacketRecord

@dataclass
class FlowRecord:
    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    first_seen: float
    last_seen: float
    packets_forward: int = 0
    packets_reverse: int = 0
    bytes_forward: int = 0
    bytes_reverse: int = 0
    flags_seen: List[str] = field(default_factory=list)

    @property
    def total_packets(self) -> int:
        return self.packets_forward + self.packets_reverse

    @property
    def total_bytes(self) -> int:
        return self.bytes_forward + self.bytes_reverse

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

class FlowTracker:
    def __init__(self, idle_timeout: float = 120.0, max_flows: int = 10000):
        self.idle_timeout = idle_timeout
        self.max_flows = max_flows
        self.flows: Dict[str, FlowRecord] = {}

    def update(self, record: PacketRecord) -> FlowRecord:
        """Updates or registers a flow with the observed packet record."""
        now = record.timestamp or time.time()
        key = record.flow_key

        if key in self.flows:
            flow = self.flows[key]
            flow.last_seen = now
            if record.src_ip == flow.src_ip:
                flow.packets_forward += 1
                flow.bytes_forward += record.packet_length
            else:
                flow.packets_reverse += 1
                flow.bytes_reverse += record.packet_length
            if record.tcp_flags and record.tcp_flags not in flow.flags_seen:
                flow.flags_seen.append(record.tcp_flags)
            return flow

        # Flow table size protection
        if len(self.flows) >= self.max_flows:
            self.expire_idle_flows(now, force_lru=True)

        flow = FlowRecord(
            flow_key=key,
            src_ip=record.src_ip,
            dst_ip=record.dst_ip,
            src_port=record.src_port,
            dst_port=record.dst_port,
            protocol=record.protocol,
            first_seen=now,
            last_seen=now,
            packets_forward=1,
            bytes_forward=record.packet_length,
            flags_seen=[record.tcp_flags] if record.tcp_flags else []
        )
        self.flows[key] = flow
        return flow

    def expire_idle_flows(self, current_time: Optional[float] = None, force_lru: bool = False) -> int:
        """Evicts flows that have been idle longer than idle_timeout or LRU when bounded."""
        now = current_time or time.time()
        expired_keys = [
            k for k, f in self.flows.items()
            if (now - f.last_seen) > self.idle_timeout
        ]
        
        # If forced to free space and no idle flows found, evict oldest 10%
        if force_lru and len(expired_keys) == 0 and self.flows:
            sorted_keys = sorted(self.flows.keys(), key=lambda k: self.flows[k].last_seen)
            evict_count = max(1, int(len(sorted_keys) * 0.1))
            expired_keys.extend(sorted_keys[:evict_count])

        for k in expired_keys:
            self.flows.pop(k, None)

        return len(expired_keys)

    def active_flows_count(self) -> int:
        return len(self.flows)
