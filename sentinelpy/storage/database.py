"""
SentinelPy IDS - SQLite Storage Adapter
Provides persistent, indexed event storage for SOC historical querying.
"""

import sqlite3
import json
import threading
from typing import List, Dict, Any, Optional
from sentinelpy.alerts.models import AlertEvent

class DatabaseStorage:
    def __init__(self, db_path: str = "sentinelpy.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE,
                    timestamp TEXT,
                    rule_id TEXT,
                    rule_name TEXT,
                    detection_type TEXT,
                    severity TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    protocol TEXT,
                    evidence_json TEXT,
                    sensor TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts (rule_id);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts (src_ip);")
            conn.commit()
            conn.close()

    def save_alert(self, alert: AlertEvent):
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO alerts (
                    event_id, timestamp, rule_id, rule_name,
                    detection_type, severity, src_ip, dst_ip,
                    protocol, evidence_json, sensor
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.event_id,
                alert.timestamp,
                alert.rule_id,
                alert.rule_name,
                alert.detection_type,
                alert.severity,
                alert.src_ip,
                alert.dst_ip,
                alert.protocol,
                json.dumps(alert.evidence),
                alert.sensor
            ))
            conn.commit()
            conn.close()

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, event_id, timestamp, rule_id, rule_name,
                       detection_type, severity, src_ip, dst_ip, protocol,
                       evidence_json, sensor
                FROM alerts
                ORDER BY id DESC
                LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                try:
                    item["evidence"] = json.loads(item["evidence_json"])
                except Exception:
                    item["evidence"] = {}
                results.append(item)
            conn.close()
            return results

    def get_alert_count(self) -> int:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM alerts")
            count = cursor.fetchone()[0]
            conn.close()
            return count
