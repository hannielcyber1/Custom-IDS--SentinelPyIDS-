"""
SentinelPy IDS - Webhook / Slack Alert Notifier
Dispatches asynchronous JSON webhook notifications to Slack or generic SIEM receivers.
"""

import threading
from typing import Dict, Any, Optional
import requests

from sentinelpy.alerts.models import AlertEvent

SEVERITY_RANKS = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

class WebhookNotifier:
    """Sends asynchronous HTTP POST notifications for alert events."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        self.enabled: bool = cfg.get("enabled", False)
        self.url: str = cfg.get("url", "")
        self.format: str = cfg.get("format", "slack").lower()
        self.min_severity: str = cfg.get("min_severity", "medium").lower()

    def _meets_min_severity(self, severity: str) -> bool:
        alert_rank = SEVERITY_RANKS.get(severity.lower(), 0)
        min_rank = SEVERITY_RANKS.get(self.min_severity.lower(), 2)
        return alert_rank >= min_rank

    def _build_payload(self, alert: AlertEvent) -> Dict[str, Any]:
        sev = alert.severity.lower()
        if self.format == "slack":
            color = "danger" if sev in ("critical", "high") else ("warning" if sev == "medium" else "good")
            return {
                "text": f"[{alert.severity.upper()}] {alert.rule_name}",
                "attachments": [
                    {
                        "color": color,
                        "title": f"{alert.rule_name} ({alert.rule_id})",
                        "fields": [
                            {"title": "Severity", "value": alert.severity.upper(), "short": True},
                            {"title": "Protocol", "value": alert.protocol.upper(), "short": True},
                            {"title": "Source", "value": alert.src_ip, "short": True},
                            {"title": "Destination", "value": alert.dst_ip, "short": True},
                            {"title": "Timestamp", "value": str(alert.timestamp), "short": False},
                            {"title": "Evidence", "value": str(alert.evidence), "short": False},
                        ],
                    }
                ],
            }
        else: # generic
            return {
                "rule_id": alert.rule_id,
                "rule_name": alert.rule_name,
                "severity": alert.severity,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "protocol": alert.protocol,
                "timestamp": alert.timestamp,
                "evidence": alert.evidence,
            }

    def send(self, alert: AlertEvent, sync: bool = False) -> None:
        """Sends alert if enabled and severity meets the threshold."""
        if not self.enabled or not self.url:
            return

        if not self._meets_min_severity(alert.severity):
            return

        if sync:
            self._post_worker(alert)
        else:
            t = threading.Thread(target=self._post_worker, args=(alert,), daemon=True)
            t.start()

    def _post_worker(self, alert: AlertEvent) -> None:
        try:
            payload = self._build_payload(alert)
            requests.post(self.url, json=payload, timeout=5)
        except Exception:
            # Silent fallback to protect packet inspection loop
            pass
