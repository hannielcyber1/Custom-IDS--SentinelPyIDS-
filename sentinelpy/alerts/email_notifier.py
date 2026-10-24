"""
SentinelPy IDS - Email Alert Notifier
Handles asynchronous SMTP dispatch for high-severity alerts with cooldown logic.
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import time
from typing import Dict, Any, Optional
from collections import defaultdict

class EmailNotifier:
    def __init__(self, config: Dict[str, Any]):
        self.enabled = config.get("enabled", False)
        self.smtp_server = config.get("smtp_server", "smtp.gmail.com")
        self.smtp_port = config.get("smtp_port", 587)
        self.use_tls = config.get("use_tls", True)
        self.sender_email = config.get("sender_email", "")
        self.sender_password = config.get("sender_password", "")
        self.admin_email = config.get("admin_email", "")
        self.cooldown_seconds = config.get("cooldown_seconds", 60)
        self._last_alert_time: Dict[str, float] = defaultdict(float)

    def should_alert(self, key: str) -> bool:
        if not self.enabled:
            return False
        now = time.time()
        if now - self._last_alert_time[key] >= self.cooldown_seconds:
            self._last_alert_time[key] = now
            return True
        return False

    def send_notification(self, subject: str, body: str, alert_key: Optional[str] = None, sync: bool = False):
        if not self.enabled:
            return

        if alert_key and not self.should_alert(alert_key):
            return

        if sync:
            self._send_mail_worker(subject, body)
        else:
            t = threading.Thread(target=self._send_mail_worker, args=(subject, body), daemon=True)
            t.start()

    def _send_mail_worker(self, subject: str, body: str):
        try:
            msg = MIMEMultipart()
            msg["From"] = self.sender_email
            msg["To"] = self.admin_email
            msg["Subject"] = f"[SENTINEL-IDS] {subject}"
            msg.attach(MIMEText(body, "plain"))

            server = smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=10)
            if self.use_tls:
                server.starttls()
            if self.sender_email and self.sender_password:
                server.login(self.sender_email, self.sender_password)
            server.send_message(msg)
            server.quit()
        except Exception:
            # Silent fallback so network packet processing is never disrupted
            pass
