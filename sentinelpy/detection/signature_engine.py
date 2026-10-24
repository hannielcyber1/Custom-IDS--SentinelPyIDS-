"""
SentinelPy IDS - Signature Detection Engine
Evaluates packet records against indexed candidate signature rules.
"""

import re
from typing import List, Optional, Dict, Pattern
from sentinelpy.rules.models import SignatureRule, ContentMatch, TcpFlagsMatch
from sentinelpy.core.packet_record import PacketRecord
from sentinelpy.core.flowbits import FlowBitTracker
from sentinelpy.alerts.models import AlertEvent

class SignatureEngine:
    def __init__(self, sensor_id: str = "sentinelpy-lab", flowbit_tracker: Optional[FlowBitTracker] = None):
        self.sensor_id = sensor_id
        self._regex_cache: Dict[str, Pattern] = {}
        self.flowbits = flowbit_tracker or FlowBitTracker()

    def matches(self, rule: SignatureRule, record: PacketRecord) -> bool:
        """Evaluates whether the record satisfies all conditions of the signature rule."""
        match = rule.match
        
        # 1. Protocol check
        if match.protocol.lower() != "ip" and match.protocol.lower() != record.protocol.lower():
            return False

        # 2. Source / Destination IP
        if match.source_ip and match.source_ip != record.src_ip:
            return False
        if match.destination_ip and match.destination_ip != record.dst_ip:
            return False

        # 3. Source Port
        if match.source_port is not None and match.source_port != record.src_port:
            return False

        # 4. Destination Port(s)
        if match.destination_port is not None and match.destination_port != record.dst_port:
            return False
        if match.destination_ports and (record.dst_port not in match.destination_ports):
            return False

        # 4b. Either Source or Destination Port(s)
        if match.ports:
            in_src = record.src_port in match.ports if record.src_port is not None else False
            in_dst = record.dst_port in match.ports if record.dst_port is not None else False
            if not (in_src or in_dst):
                return False

        # 5. TCP Flags
        if match.tcp_flags:
            if isinstance(match.tcp_flags, str):
                if match.tcp_flags not in record.tcp_flags:
                    return False
            elif isinstance(match.tcp_flags, TcpFlagsMatch):
                if match.tcp_flags.contains and match.tcp_flags.contains not in record.tcp_flags:
                    return False
                if match.tcp_flags.exact and match.tcp_flags.exact != record.tcp_flags:
                    return False

        # 6. ICMP Type & Code
        if match.icmp_type is not None and match.icmp_type != record.icmp_type:
            return False
        if match.icmp_code is not None and match.icmp_code != record.icmp_code:
            return False

        # 7. Content matching in payload
        if match.content:
            text = record.payload_text
            if not text:
                return False

            if isinstance(match.content, str):
                if match.content.lower() not in text.lower():
                    return False
            elif isinstance(match.content, ContentMatch):
                search_text = text.lower() if match.content.nocase else text
                if match.content.any_of:
                    found = False
                    for pattern in match.content.any_of:
                        target = pattern.lower() if match.content.nocase else pattern
                        if target in search_text:
                            found = True
                            break
                    if not found:
                        return False
                if match.content.exact:
                    target = match.content.exact.lower() if match.content.nocase else match.content.exact
                    if target != search_text:
                        return False

        # 8. Deep Packet Inspection: Regular Expression (PCRE/Regex)
        if match.regex:
            if not record.payload_text:
                return False
            if match.regex not in self._regex_cache:
                self._regex_cache[match.regex] = re.compile(match.regex)
            if not self._regex_cache[match.regex].search(record.payload_text):
                return False

        # 9. Deep Packet Inspection: Binary Magic Bytes / Hex patterns
        if match.magic_bytes:
            if not record.payload_bytes:
                return False
            try:
                clean_hex = match.magic_bytes.replace(" ", "").replace("0x", "")
                target_bytes = bytes.fromhex(clean_hex)
                if target_bytes not in record.payload_bytes:
                    return False
            except Exception:
                return False

        # 10. Deep Packet Inspection: Encrypted Traffic TLS SNI Extraction
        if match.tls_sni:
            if not record.tls_sni:
                return False
            if isinstance(match.tls_sni, str):
                if match.tls_sni.lower() not in record.tls_sni:
                    return False
            elif isinstance(match.tls_sni, list):
                if not any(item.lower() in record.tls_sni for item in match.tls_sni):
                    return False

        # 11. JA3 TLS fingerprint matching
        if match.ja3:
            if not record.ja3 or record.ja3 != match.ja3:
                return False
        if match.ja3_list:
            if not record.ja3 or record.ja3 not in match.ja3_list:
                return False

        # 12. HTTP protocol field matching
        if match.http_method:
            if not record.http_method or record.http_method.upper() != match.http_method.upper():
                return False
        if match.http_uri:
            if not record.http_uri or match.http_uri.lower() not in record.http_uri.lower():
                return False
        if match.http_user_agent:
            if not record.http_user_agent or match.http_user_agent.lower() not in record.http_user_agent.lower():
                return False

        # 13. GeoIP country filter — match if src OR dst country in list
        if match.geoip_country:
            countries = [match.geoip_country] if isinstance(match.geoip_country, str) else match.geoip_country
            countries_upper = [c.upper() for c in countries]
            src_match = (record.src_country or "").upper() in countries_upper
            dst_match = (record.dst_country or "").upper() in countries_upper
            if not (src_match or dst_match):
                return False

        # 14. Flowbits — check prerequisite flag is set on this flow
        if match.flowbits_isset:
            if not self.flowbits.isset_bit(record.flow_key, match.flowbits_isset):
                return False

        return True

    def apply_flowbits(self, rule: SignatureRule, record: PacketRecord) -> None:
        """Called after a rule fires to apply any flowbits_set side-effects."""
        if rule.match.flowbits_set:
            self.flowbits.set_bit(record.flow_key, rule.match.flowbits_set)

    def build_alert(self, rule: SignatureRule, record: PacketRecord) -> AlertEvent:
        evidence = {
            "packet_length": record.packet_length,
            "tcp_flags": record.tcp_flags,
            "rule_category": rule.category
        }
        if record.payload_text:
            evidence["payload_snippet"] = record.payload_text[:120].strip()
        if record.tls_sni:
            evidence["tls_sni"] = record.tls_sni
        if record.ja3:
            evidence["ja3"] = record.ja3
        if record.http_method:
            evidence["http_method"] = record.http_method
        if record.http_uri:
            evidence["http_uri"] = record.http_uri
        if record.http_user_agent:
            evidence["http_user_agent"] = record.http_user_agent
        if record.src_country:
            evidence["src_country"] = record.src_country
        if record.dst_country:
            evidence["dst_country"] = record.dst_country
        if record.src_isp:
            evidence["src_isp"] = record.src_isp
        if rule.match.magic_bytes:
            evidence["matched_magic_bytes"] = rule.match.magic_bytes
        if rule.match.regex:
            evidence["matched_regex"] = rule.match.regex

        return AlertEvent(
            rule_id=rule.id,
            rule_name=rule.name,
            detection_type="signature",
            severity=rule.severity,
            src_ip=record.src_ip,
            dst_ip=record.dst_ip,
            protocol=record.protocol,
            evidence=evidence,
            sensor=self.sensor_id
        )
