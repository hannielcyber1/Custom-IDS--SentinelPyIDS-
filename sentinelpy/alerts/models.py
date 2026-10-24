"""
SentinelPy IDS - Standard Alert Schema
Matches the production EVE JSON / SOC standard format.
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, Any, Optional
import datetime
import uuid
import json

@dataclass
class AlertEvent:
    rule_id: str
    rule_name: str
    detection_type: str
    severity: str
    src_ip: str
    dst_ip: str
    protocol: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    sensor: str = "sentinelpy-lab"
    status: str = "new"
    timestamp: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    event_id: str = field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())
