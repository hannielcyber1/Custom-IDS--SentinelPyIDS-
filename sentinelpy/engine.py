"""
SentinelPy IDS/IPS - Main Engine Coordinator
Orchestrates: normalization → GeoIP enrichment → IP reputation → flow tracking →
flowbits → signature detection → behavioral detection → IPS blocking →
file extraction → metrics.
"""

import time
import dataclasses
import threading
from typing import Optional, List

from sentinelpy.core.packet_record import normalize_packet, PacketRecord
from sentinelpy.core.flow_tracker import FlowTracker
from sentinelpy.core.flowbits import FlowBitTracker
from sentinelpy.rules.loader import RuleCatalog
from sentinelpy.detection.signature_engine import SignatureEngine
from sentinelpy.detection.behavior_engine import BehaviorEngine
from sentinelpy.alerts.manager import AlertManager
from sentinelpy.alerts.models import AlertEvent
from sentinelpy.monitoring.metrics import MetricsCollector
from sentinelpy.enrichment.geoip import GeoIPLookup
from sentinelpy.enrichment.ip_reputation import IPReputationChecker
from sentinelpy.ips.blocker import IPSBlocker
from sentinelpy.extraction.file_extractor import FileExtractor


class SentinelEngine:
    def __init__(
        self,
        catalog: RuleCatalog,
        alert_manager: AlertManager,
        metrics: MetricsCollector,
        flow_tracker: Optional[FlowTracker] = None,
        sensor_id: str = "sentinelpy-lab",
        geoip: Optional[GeoIPLookup] = None,
        ip_reputation: Optional[IPReputationChecker] = None,
        ips_blocker: Optional[IPSBlocker] = None,
        file_extractor: Optional[FileExtractor] = None,
    ):
        self.catalog         = catalog
        self.alert_manager   = alert_manager
        self.metrics         = metrics
        self.flow_tracker    = flow_tracker or FlowTracker()
        self.flowbits        = FlowBitTracker()
        self.signature_engine = SignatureEngine(sensor_id=sensor_id, flowbit_tracker=self.flowbits)
        self.behavior_engine  = BehaviorEngine(self.catalog.behavioral_rules, sensor_id=sensor_id)
        self.geoip           = geoip
        self.ip_reputation   = ip_reputation
        self.ips_blocker     = ips_blocker
        self.file_extractor  = file_extractor
        self.sensor_id       = sensor_id

        # Background flush thread for file extractor idle flows
        self._stop_event = threading.Event()
        if file_extractor and file_extractor.enabled:
            self._flush_thread = threading.Thread(
                target=self._flush_loop, daemon=True, name="sentinelpy-file-flush"
            )
            self._flush_thread.start()
        else:
            self._flush_thread = None

    # ------------------------------------------------------------------
    def _flush_loop(self):
        """Periodically flush idle flow buffers in the file extractor."""
        while not self._stop_event.wait(10):
            if self.file_extractor:
                extractions = self.file_extractor.flush_idle()
                for meta in extractions:
                    self._emit_extraction_alert(meta)

    def _emit_extraction_alert(self, meta: dict):
        alert = AlertEvent(
            rule_id="SNT-EXTRACT-001",
            rule_name=f"FILE-EXTRACTION {meta['file_type']} Detected in Network Stream",
            detection_type="file-extraction",
            severity="high",
            src_ip=meta["src_ip"],
            dst_ip=meta["dst_ip"],
            protocol=meta["protocol"],
            evidence={
                "file_path":   meta["file_path"],
                "file_type":   meta["file_type"],
                "size_bytes":  meta["size_bytes"],
                "flow_key":    meta["flow_key"],
                "extracted_at": meta["extracted_at"],
            },
            sensor=self.sensor_id,
        )
        if self.alert_manager.emit(alert):
            self.metrics.record_alert()

    # ------------------------------------------------------------------
    def _enrich_geoip(self, record: PacketRecord) -> PacketRecord:
        if not self.geoip:
            return record
        src_info = self.geoip.lookup(record.src_ip) or {}
        dst_info = self.geoip.lookup(record.dst_ip) or {}
        return dataclasses.replace(
            record,
            src_country=src_info.get("countryCode"),
            dst_country=dst_info.get("countryCode"),
            src_isp=src_info.get("isp"),
        )

    def _check_ip_reputation(self, record: PacketRecord):
        if not self.ip_reputation:
            return
        for ip, direction in ((record.src_ip, "source"), (record.dst_ip, "destination")):
            if self.ip_reputation.is_blocked(ip):
                alert = AlertEvent(
                    rule_id="SNT-THREAT-INTEL-001",
                    rule_name="THREAT-INTEL Known Malicious IP",
                    detection_type="threat-intel",
                    severity="critical",
                    src_ip=record.src_ip,
                    dst_ip=record.dst_ip,
                    protocol=record.protocol,
                    evidence={
                        "blocked_ip": ip,
                        "direction":  direction,
                        "source":     "Feodo/AbuseCH Blocklist",
                        "packet_length": record.packet_length,
                    },
                    sensor=self.sensor_id,
                )
                if self.alert_manager.emit(alert):
                    self.metrics.record_alert()
                # Auto-block via IPS if enabled
                if self.ips_blocker and self.ips_blocker.should_block("critical"):
                    self.ips_blocker.block(
                        record.src_ip,
                        reason="Known malicious IP (Feodo/AbuseCH)",
                        rule_id="SNT-THREAT-INTEL-001",
                    )

    def _maybe_block(self, alert: AlertEvent, record: PacketRecord):
        """After an alert fires, apply IPS block if configured."""
        if not self.ips_blocker:
            return
        if self.ips_blocker.should_block(alert.severity):
            self.ips_blocker.block(
                record.src_ip,
                reason=alert.rule_name,
                rule_id=alert.rule_id,
            )

    def _feed_extractor(self, record: PacketRecord):
        """Feed packet payload into the file extractor for this flow."""
        if not self.file_extractor or not record.payload_bytes:
            return
        meta = self.file_extractor.observe(
            flow_key=record.flow_key,
            src_ip=record.src_ip,
            dst_ip=record.dst_ip,
            protocol=record.protocol,
            payload=record.payload_bytes,
        )
        if meta:
            self._emit_extraction_alert(meta)

    # ------------------------------------------------------------------
    def process_packet(self, raw_pkt):
        """Full detection pipeline for a single raw packet."""
        t_start = time.perf_counter()
        pkt_len = len(raw_pkt)

        # 1. Normalization (includes JA3 + HTTP parsing)
        record = normalize_packet(raw_pkt)
        if record is None:
            self.metrics.record_packet(pkt_len, valid=False)
            return

        # 2. GeoIP Enrichment
        record = self._enrich_geoip(record)

        # 3. IP Reputation / Blocklist check
        self._check_ip_reputation(record)

        # 4. Flow Tracking
        self.flow_tracker.update(record)

        # 5. File Extraction (TCP stream reassembly)
        self._feed_extractor(record)

        # 6. Signature-based Inspection
        for rule in self.catalog.get_candidate_signatures(record):
            if self.signature_engine.matches(rule, record):
                alert = self.signature_engine.build_alert(rule, record)
                if self.alert_manager.emit(alert):
                    self.metrics.record_alert()
                    # IPS: block the source IP if severity warrants it
                    self._maybe_block(alert, record)
                # Apply flowbits_set side-effect
                self.signature_engine.apply_flowbits(rule, record)

        # 7. Behavioral Anomaly Inspection
        for b_alert in self.behavior_engine.observe(record):
            if self.alert_manager.emit(b_alert):
                self.metrics.record_alert()
                self._maybe_block(b_alert, record)

        # 8. Metrics
        latency = time.perf_counter() - t_start
        self.metrics.record_packet(pkt_len, valid=True, latency=latency)

    def stop(self):
        """Cleanly stop background threads."""
        self._stop_event.set()
        if self.ips_blocker:
            self.ips_blocker.stop()
