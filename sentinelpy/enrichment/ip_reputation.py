"""
SentinelPy IDS - Threat Intelligence IP Reputation & Blocklist Checker
Provides O(1) IP reputation lookups against known malicious C2 and botnet IPs.
"""

import os
from typing import Set, Optional
import requests

DEFAULT_BLOCKLIST_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt"
DEFAULT_SAVE_PATH = "rules/blocklist/feodo_blocklist.txt"

class IPReputationChecker:
    """Manages active IP blocklists and evaluates packets against threat intel feeds."""

    def __init__(self, blocklist_path: Optional[str] = None):
        self._blocked_ips: Set[str] = set()
        self.blocklist_path = blocklist_path
        if blocklist_path and os.path.exists(blocklist_path):
            self.load_blocklist(blocklist_path)

    def load_blocklist(self, path: str) -> int:
        """
        Loads IP addresses from a local text file.
        Lines starting with '#' and whitespace are ignored.
        """
        if not os.path.exists(path):
            return 0

        loaded = 0
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Support lines that might include comments or port numbers like ip:port
                ip = line.split()[0].split(":")[0].strip()
                if ip:
                    self._blocked_ips.add(ip)
                    loaded += 1

        self.blocklist_path = path
        return len(self._blocked_ips)

    def download_blocklist(
        self,
        url: str = DEFAULT_BLOCKLIST_URL,
        save_path: str = DEFAULT_SAVE_PATH
    ) -> int:
        """
        Downloads a blocklist file from the given URL and saves it locally.
        Reloads the internal set of blocked IPs upon completion.
        """
        parent_dir = os.path.dirname(save_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)

        resp = requests.get(url, timeout=30)
        resp.raise_for_status()

        with open(save_path, "w", encoding="utf-8") as f:
            f.write(resp.text)

        return self.load_blocklist(save_path)

    def is_blocked(self, ip: str) -> bool:
        """O(1) lookup to determine if the given IP is blocked."""
        if not ip:
            return False
        return ip in self._blocked_ips

    def blocked_count(self) -> int:
        """Returns the total number of currently loaded blocked IP addresses."""
        return len(self._blocked_ips)

    def add_ip(self, ip: str) -> None:
        """Manually adds an IP to the blocklist (useful for runtime additions / tests)."""
        if ip:
            self._blocked_ips.add(ip.strip())

    def clear(self) -> None:
        self._blocked_ips.clear()
