"""
SentinelPy IDS - JSONL & Text Log Storage
Provides append-only structured streaming event logs (SIEM ingestible).
"""

import threading
import os
from typing import Optional
from sentinelpy.alerts.models import AlertEvent

class JsonlWriter:
    def __init__(self, jsonl_path: str = "alerts.jsonl", text_log_path: Optional[str] = "ids_alerts.log"):
        self.jsonl_path = jsonl_path
        self.text_log_path = text_log_path
        self._lock = threading.Lock()

    def write_alert(self, alert: AlertEvent):
        line = alert.to_json() + "\n"
        with self._lock:
            # 1. Write structured JSON Lines
            try:
                with open(self.jsonl_path, "a", encoding="utf-8") as f:
                    f.write(line)
            except Exception:
                pass

            # 2. Write readable text log
            if self.text_log_path:
                try:
                    summary = f"[{alert.timestamp}] ALERT: [{alert.severity.upper()}] {alert.rule_name} ({alert.rule_id}) - {alert.src_ip} -> {alert.dst_ip}:{alert.protocol} Evidence: {alert.evidence}\n"
                    with open(self.text_log_path, "a", encoding="utf-8") as f:
                        f.write(summary)
                except Exception:
                    pass
