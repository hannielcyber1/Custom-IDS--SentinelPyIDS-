"""
SentinelPy IDS - Alert Manager
Handles alert deduplication, severity grading, terminal visualization, and storage dispatch.
"""

import time
import os
from collections import defaultdict
from typing import Dict, Any, Optional

from sentinelpy.alerts.models import AlertEvent
from sentinelpy.storage.database import DatabaseStorage
from sentinelpy.storage.jsonl_writer import JsonlWriter
from sentinelpy.alerts.email_notifier import EmailNotifier
from sentinelpy.alerts.webhook_notifier import WebhookNotifier

# ANSI Terminal Colors
os.system("")
class TermColors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

SEVERITY_COLORS = {
    "informational": TermColors.CYAN,
    "low": TermColors.BLUE,
    "medium": TermColors.YELLOW,
    "high": TermColors.RED,
    "critical": TermColors.RED + TermColors.BOLD
}

class AlertManager:
    def __init__(
        self,
        db_storage: DatabaseStorage,
        jsonl_writer: JsonlWriter,
        email_notifier: EmailNotifier,
        cooldown_seconds: float = 60.0,
        sensor_name: str = "sentinelpy-lab",
        webhook_notifier: Optional[WebhookNotifier] = None,
    ):
        self.db = db_storage
        self.writer = jsonl_writer
        self.notifier = email_notifier
        self.webhook = webhook_notifier
        self.cooldown_seconds = cooldown_seconds
        self.sensor_name = sensor_name
        
        # Deduplication cache: (rule_id, src_ip, dst_ip) -> last_alert_time
        self._last_alert_time: Dict[str, float] = defaultdict(float)

    def emit(self, alert: AlertEvent) -> bool:
        """Processes, deduplicates, stores, and notifies on an alert."""
        now = time.time()
        dedup_key = f"{alert.rule_id}:{alert.src_ip}->{alert.dst_ip}"
        
        # Check cooldown to prevent alert flooding
        if now - self._last_alert_time[dedup_key] < self.cooldown_seconds:
            return False
            
        self._last_alert_time[dedup_key] = now

        # 1. Print formatted alert to Console
        color = SEVERITY_COLORS.get(alert.severity.lower(), TermColors.WHITE)
        sev_tag = f"[{alert.severity.upper()}]"
        print(f"{color}{TermColors.BOLD}[!] ALERT {sev_tag} {alert.rule_name} ({alert.rule_id}){TermColors.RESET}")
        print(f"    {TermColors.WHITE}Source:{TermColors.RESET} {alert.src_ip} -> {TermColors.WHITE}Target:{TermColors.RESET} {alert.dst_ip} ({alert.protocol.upper()})")
        if alert.evidence:
            print(f"    {TermColors.WHITE}Evidence:{TermColors.RESET} {alert.evidence}")

        # 2. Persist to SQLite
        self.db.save_alert(alert)

        # 3. Stream to JSONL / Log file
        self.writer.write_alert(alert)

        # 4. Trigger Email Notification if high/medium severity or configured
        if alert.severity.lower() in ("medium", "high", "critical"):
            subject = f"[{alert.severity.upper()}] {alert.rule_name} from {alert.src_ip}"
            body = (
                f"SentinelPy Alert Triggered\n"
                f"===========================\n"
                f"Rule: {alert.rule_name} (ID: {alert.rule_id})\n"
                f"Type: {alert.detection_type}\n"
                f"Severity: {alert.severity.upper()}\n"
                f"Source: {alert.src_ip}\n"
                f"Destination: {alert.dst_ip}\n"
                f"Protocol: {alert.protocol}\n"
                f"Timestamp: {alert.timestamp}\n"
                f"Evidence:\n{alert.evidence}\n"
            )
            self.notifier.send_notification(subject, body, alert_key=dedup_key)

        # 5. Webhook / Slack notification
        if self.webhook:
            self.webhook.send(alert)

        return True
