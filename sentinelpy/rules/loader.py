"""
SentinelPy IDS - Rule Loader & Indexer
Loads, validates, and indexes signature and behavioral rules.
"""

import os
import yaml
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set
from collections import defaultdict

from sentinelpy.rules.models import SignatureRule, BehavioralRule, RuleFile
from sentinelpy.core.packet_record import PacketRecord

class RuleValidationError(Exception):
    pass

class RuleCatalog:
    def __init__(self):
        self.signature_rules: List[SignatureRule] = []
        self.behavioral_rules: List[BehavioralRule] = []
        self._seen_ids: Set[str] = set()
        
        # Fast candidate indices for signatures
        # protocol -> list of rules
        self._protocol_index: Dict[str, List[SignatureRule]] = defaultdict(list)
        # (protocol, port) -> list of rules
        self._port_index: Dict[Tuple[str, int], List[SignatureRule]] = defaultdict(list)
        # generic protocol rules (no specific port)
        self._generic_index: Dict[str, List[SignatureRule]] = defaultdict(list)

    def load_from_directory(self, sig_dir: str, behav_dir: str) -> Tuple[int, int]:
        """Loads rules from signature and behavioral directories."""
        sig_count = 0
        behav_count = 0
        
        sig_path = Path(sig_dir)
        if sig_path.exists():
            for yaml_file in sig_path.glob("*.yaml"):
                sig_count += self.load_signature_file(str(yaml_file))

        behav_path = Path(behav_dir)
        if behav_path.exists():
            for yaml_file in behav_path.glob("*.yaml"):
                behav_count += self.load_behavioral_file(str(yaml_file))

        return sig_count, behav_count

    def load_signature_file(self, file_path: str) -> int:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or "rules" not in data:
            return 0

        rule_file = RuleFile(**data)
        count = 0
        for raw_rule in rule_file.rules:
            sig = SignatureRule(**raw_rule)
            if sig.id in self._seen_ids:
                raise RuleValidationError(f"Duplicate rule ID detected: {sig.id}")
            self._seen_ids.add(sig.id)
            if sig.enabled:
                self.add_signature_rule(sig)
                count += 1
        return count

    def load_behavioral_file(self, file_path: str) -> int:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or "rules" not in data:
            return 0

        rule_file = RuleFile(**data)
        count = 0
        for raw_rule in rule_file.rules:
            behav = BehavioralRule(**raw_rule)
            if behav.id in self._seen_ids:
                raise RuleValidationError(f"Duplicate rule ID detected: {behav.id}")
            self._seen_ids.add(behav.id)
            if behav.enabled:
                self.behavioral_rules.append(behav)
                count += 1
        return count

    def add_signature_rule(self, rule: SignatureRule):
        self.signature_rules.append(rule)
        proto = rule.match.protocol.lower()
        self._protocol_index[proto].append(rule)

        ports = []
        if rule.match.destination_port:
            ports.append(rule.match.destination_port)
        if rule.match.destination_ports:
            ports.extend(rule.match.destination_ports)
        if rule.match.ports:
            ports.extend(rule.match.ports)

        if ports:
            for p in ports:
                self._port_index[(proto, p)].append(rule)
        else:
            self._generic_index[proto].append(rule)

    def get_candidate_signatures(self, record: PacketRecord) -> List[SignatureRule]:
        """Returns only signature rules applicable to this packet record (avoids full scan)."""
        proto = record.protocol.lower()
        candidates: List[SignatureRule] = []
        
        # 1. Any rules specific to this protocol and destination or source port
        seen_ids = set()
        if record.dst_port is not None:
            for r in self._port_index.get((proto, record.dst_port), []):
                if r.id not in seen_ids:
                    seen_ids.add(r.id)
                    candidates.append(r)
        if record.src_port is not None:
            for r in self._port_index.get((proto, record.src_port), []):
                if r.id not in seen_ids:
                    seen_ids.add(r.id)
                    candidates.append(r)

        # 2. Any generic rules for this protocol (no port restriction)
        for r in self._generic_index.get(proto, []):
            if r.id not in seen_ids:
                seen_ids.add(r.id)
                candidates.append(r)

        # 3. Any global IP rules if packet has an IP layer
        if proto in ("tcp", "udp", "icmp"):
            for r in self._generic_index.get("ip", []):
                if r.id not in seen_ids:
                    seen_ids.add(r.id)
                    candidates.append(r)

        return candidates
