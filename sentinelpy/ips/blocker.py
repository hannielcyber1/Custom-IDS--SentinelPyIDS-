"""
SentinelPy IDS/IPS - Active Blocking Engine
Uses Windows Firewall (netsh advfirewall) to drop traffic from malicious source IPs.
Requires the process to be running as Administrator.

Blocked IPs are tracked in SQLite with an expiry time and automatically
un-blocked by a background thread when the block duration expires.

Usage:
    blocker = IPSBlocker(db_path="sentinelpy.db", block_duration_minutes=60)
    blocker.start()                     # starts background expiry thread
    blocker.block("1.2.3.4", reason="Shellcode detected")
    blocker.unblock("1.2.3.4")
    blocker.list_blocks()               # returns list of active blocks
    blocker.stop()                      # stops the expiry thread
"""

import subprocess
import sqlite3
import threading
import time
import logging
import platform
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

logger = logging.getLogger("sentinelpy.ips")

_IS_WINDOWS = platform.system() == "Windows"

RULE_PREFIX = "SentinelPy-IPS-Block"


def _firewall_add(ip: str) -> bool:
    """Add an inbound block rule via netsh (Windows) or iptables (Linux/Mac)."""
    try:
        if _IS_WINDOWS:
            rule_name = f"{RULE_PREFIX}-{ip}"
            result = subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip}",
                    "protocol=any",
                    "enable=yes",
                    "profile=any",
                ],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        else:
            # Linux / Mac fallback using iptables
            result = subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
    except Exception as exc:
        logger.error("firewall_add(%s) failed: %s", ip, exc)
        return False


def _firewall_remove(ip: str) -> bool:
    """Remove the inbound block rule for this IP."""
    try:
        if _IS_WINDOWS:
            rule_name = f"{RULE_PREFIX}-{ip}"
            result = subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}",
                ],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        else:
            result = subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
    except Exception as exc:
        logger.error("firewall_remove(%s) failed: %s", ip, exc)
        return False


class IPSBlocker:
    """
    Active IPS blocking engine.

    Blocks are persisted to SQLite so they survive process restarts.
    A background daemon thread periodically checks for expired blocks and removes them.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS ips_blocks (
        ip          TEXT PRIMARY KEY,
        reason      TEXT,
        rule_id     TEXT,
        blocked_at  TEXT,
        expires_at  TEXT,
        active      INTEGER DEFAULT 1
    );
    """

    def __init__(
        self,
        db_path: str = "sentinelpy.db",
        block_duration_minutes: int = 60,
        auto_block_severities: Optional[List[str]] = None,
        enabled: bool = True,
        dry_run: bool = False,
    ):
        self.db_path              = db_path
        self.block_duration       = timedelta(minutes=block_duration_minutes)
        self.auto_block_severities = set(s.lower() for s in (auto_block_severities or ["critical", "high"]))
        self.enabled              = enabled
        self.dry_run              = dry_run   # if True, log but don't actually call netsh
        self._lock                = threading.Lock()
        self._stop_event          = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._in_memory: Dict[str, datetime] = {}  # ip -> expires_at (fast lookup)
        self._init_db()
        self._reload_active_blocks()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self._conn() as conn:
            conn.execute(self._SCHEMA)
            conn.commit()

    def _reload_active_blocks(self):
        """Restore in-memory index from DB on startup."""
        try:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT ip, expires_at FROM ips_blocks WHERE active=1"
                ).fetchall()
            now = datetime.now(timezone.utc)
            for row in rows:
                exp = datetime.fromisoformat(row["expires_at"])
                if exp > now:
                    self._in_memory[row["ip"]] = exp
                else:
                    # Already expired — clean up
                    self._expire(row["ip"])
        except Exception as exc:
            logger.warning("Could not reload IPS blocks: %s", exc)

    # ------------------------------------------------------------------
    def start(self):
        """Start the background expiry monitor thread."""
        self._thread = threading.Thread(
            target=self._expiry_loop, daemon=True, name="sentinelpy-ips-expiry"
        )
        self._thread.start()
        logger.info("IPS blocker started (dry_run=%s, duration=%s)", self.dry_run, self.block_duration)

    def stop(self):
        """Stop the background thread."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    # ------------------------------------------------------------------
    def should_block(self, severity: str) -> bool:
        return self.enabled and severity.lower() in self.auto_block_severities

    def is_blocked(self, ip: str) -> bool:
        exp = self._in_memory.get(ip)
        if exp is None:
            return False
        if datetime.now(timezone.utc) > exp:
            self._expire(ip)
            return False
        return True

    def block(self, ip: str, reason: str = "", rule_id: str = "") -> bool:
        """Block an IP. Returns True if the block was applied (or already active)."""
        if not self.enabled:
            return False
        if not ip or ip in ("0.0.0.0", "127.0.0.1"):
            return False
        if self.is_blocked(ip):
            return True  # already blocked

        now     = datetime.now(timezone.utc)
        expires = now + self.block_duration

        with self._lock:
            # Apply firewall rule
            success = True
            if not self.dry_run:
                success = _firewall_add(ip)
            else:
                logger.info("[DRY-RUN] Would block IP: %s — %s", ip, reason)

            if success or self.dry_run:
                self._in_memory[ip] = expires
                try:
                    with self._conn() as conn:
                        conn.execute(
                            """INSERT OR REPLACE INTO ips_blocks
                               (ip, reason, rule_id, blocked_at, expires_at, active)
                               VALUES (?,?,?,?,?,1)""",
                            (ip, reason, rule_id, now.isoformat(), expires.isoformat()),
                        )
                        conn.commit()
                except Exception as exc:
                    logger.warning("DB write failed for block(%s): %s", ip, exc)

                logger.warning(
                    "IPS BLOCK: %s | reason='%s' | expires=%s", ip, reason,
                    expires.strftime("%Y-%m-%d %H:%M:%S UTC")
                )
                return True
        return False

    def unblock(self, ip: str) -> bool:
        """Manually remove a block."""
        with self._lock:
            removed = False
            if not self.dry_run:
                removed = _firewall_remove(ip)
            else:
                removed = True
                logger.info("[DRY-RUN] Would unblock IP: %s", ip)

            self._in_memory.pop(ip, None)
            try:
                with self._conn() as conn:
                    conn.execute(
                        "UPDATE ips_blocks SET active=0 WHERE ip=?", (ip,)
                    )
                    conn.commit()
            except Exception:
                pass
            return removed

    def _expire(self, ip: str):
        """Called when a block has naturally expired."""
        self._in_memory.pop(ip, None)
        if not self.dry_run:
            _firewall_remove(ip)
        try:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE ips_blocks SET active=0 WHERE ip=?", (ip,)
                )
                conn.commit()
        except Exception:
            pass
        logger.info("IPS block expired and removed for %s", ip)

    def _expiry_loop(self):
        """Background thread: checks every 60 s for expired blocks."""
        while not self._stop_event.wait(60):
            now = datetime.now(timezone.utc)
            expired = [ip for ip, exp in list(self._in_memory.items()) if now > exp]
            for ip in expired:
                self._expire(ip)

    def list_blocks(self) -> List[Dict[str, Any]]:
        """Returns all currently active blocks with metadata."""
        try:
            with self._conn() as conn:
                rows = conn.execute(
                    """SELECT ip, reason, rule_id, blocked_at, expires_at
                       FROM ips_blocks WHERE active=1 ORDER BY blocked_at DESC"""
                ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def clear_all(self) -> int:
        """Removes ALL active firewall blocks. Returns count removed."""
        blocks = self.list_blocks()
        count = 0
        for b in blocks:
            if self.unblock(b["ip"]):
                count += 1
        return count
