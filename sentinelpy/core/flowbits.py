"""
SentinelPy IDS - Stateful Flowbits Tracker
Tracks stateful multi-packet detection flags (flowbits) scoped per flow key.
"""

from typing import Dict, Set
from collections import defaultdict

class FlowBitTracker:
    """Manages active flowbit flags across bidirectional network flows."""

    def __init__(self):
        self._flow_bits: Dict[str, Set[str]] = defaultdict(set)

    def set_bit(self, flow_key: str, bit_name: str) -> None:
        """Sets an active bit for the specified flow."""
        if flow_key and bit_name:
            self._flow_bits[flow_key].add(bit_name)

    def isset_bit(self, flow_key: str, bit_name: str) -> bool:
        """Returns True if the bit is currently set on the specified flow."""
        if not flow_key or not bit_name:
            return False
        return bit_name in self._flow_bits.get(flow_key, set())

    def unset_bit(self, flow_key: str, bit_name: str) -> None:
        """Removes the bit from the specified flow if present."""
        if flow_key in self._flow_bits:
            self._flow_bits[flow_key].discard(bit_name)
            if not self._flow_bits[flow_key]:
                del self._flow_bits[flow_key]

    def clear_flow(self, flow_key: str) -> None:
        """Clears all bits associated with the specified flow."""
        self._flow_bits.pop(flow_key, None)

    def get_bits(self, flow_key: str) -> Set[str]:
        """Returns a copy of active bits for the flow."""
        return set(self._flow_bits.get(flow_key, set()))
