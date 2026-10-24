"""
SentinelPy IDS - GeoIP Enrichment
Queries ip-api.com for autonomous system, ISP, and country metadata with in-memory caching.
"""

import ipaddress
from typing import Dict, Any, Optional
import requests

class GeoIPLookup:
    """In-memory cached GeoIP client using ip-api.com."""

    def __init__(self, enabled: bool = True, timeout: float = 2.0):
        self.enabled = enabled
        self.timeout = timeout
        self._cache: Dict[str, Optional[Dict[str, Any]]] = {}

    @staticmethod
    def is_private_or_loopback(ip: str) -> bool:
        """Determines if an IP is private, loopback, broadcast, or reserved."""
        if not ip or ip in ("0.0.0.0", "255.255.255.255"):
            return True
        try:
            addr = ipaddress.ip_address(ip)
            return (
                addr.is_private
                or addr.is_loopback
                or addr.is_reserved
                or addr.is_unspecified
                or addr.is_link_local
                or addr.is_multicast
            )
        except ValueError:
            return True

    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Looks up GeoIP information for an IP address.
        Returns cached result if available. Skips private/loopback addresses.
        """
        if not ip:
            return None

        if ip in self._cache:
            return self._cache[ip]

        if self.is_private_or_loopback(ip):
            self._cache[ip] = None
            return None

        if not self.enabled:
            return None

        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,isp,org,as"
        try:
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                self._cache[ip] = data
                return data
            else:
                self._cache[ip] = None
                return None
        except Exception:
            self._cache[ip] = None
            return None

    def get_country_code(self, ip: str) -> Optional[str]:
        info = self.lookup(ip)
        return info.get("countryCode") if info else None

    def get_country_name(self, ip: str) -> Optional[str]:
        info = self.lookup(ip)
        return info.get("country") if info else None

    def get_isp(self, ip: str) -> Optional[str]:
        info = self.lookup(ip)
        return info.get("isp") if info else None

    def set_cache_entry(self, ip: str, data: Optional[Dict[str, Any]]) -> None:
        """Allows pre-populating the cache (useful for testing and offline modes)."""
        self._cache[ip] = data

    def clear_cache(self) -> None:
        self._cache.clear()

_default_geoip = GeoIPLookup()

def lookup_ip(ip: str) -> Optional[Dict[str, Any]]:
    return _default_geoip.lookup(ip)
