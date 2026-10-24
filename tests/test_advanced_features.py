"""
SentinelPy IDS - Advanced Features Test Suite
Tests Active IPS Blocking, File Extraction Engine, and Stateful Flowbits Chaining.
"""

import os
import shutil
import tempfile
import pytest
from sentinelpy.ips.blocker import IPSBlocker
from sentinelpy.extraction.file_extractor import FileExtractor, detect_file_type
from sentinelpy.core.packet_record import PacketRecord
from sentinelpy.core.flowbits import FlowBitTracker
from sentinelpy.rules.models import SignatureRule, SignatureMatch
from sentinelpy.detection.signature_engine import SignatureEngine


def test_ips_blocker_lifecycle():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_ips.db")
        blocker = IPSBlocker(
            db_path=db_path,
            block_duration_minutes=10,
            enabled=True,
            dry_run=True,
        )

        assert not blocker.is_blocked("198.51.100.55")

        # Block IP
        assert blocker.block("198.51.100.55", reason="Metasploit exploit", rule_id="SNT-17529")
        assert blocker.is_blocked("198.51.100.55")

        # Duplicate block returns True without error
        assert blocker.block("198.51.100.55", reason="Metasploit exploit", rule_id="SNT-17529")

        # List blocks
        blocks = blocker.list_blocks()
        assert len(blocks) == 1
        assert blocks[0]["ip"] == "198.51.100.55"
        assert blocks[0]["rule_id"] == "SNT-17529"

        # Unblock
        assert blocker.unblock("198.51.100.55")
        assert not blocker.is_blocked("198.51.100.55")
        assert len(blocker.list_blocks()) == 0

        # Test clear_all
        blocker.block("198.51.100.1")
        blocker.block("198.51.100.2")
        assert len(blocker.list_blocks()) == 2
        cleared = blocker.clear_all()
        assert cleared == 2
        assert len(blocker.list_blocks()) == 0


def test_file_extraction_detection_and_dump():
    with tempfile.TemporaryDirectory() as tmpdir:
        extractor = FileExtractor(
            output_dir=tmpdir,
            min_detect_bytes=10,
            flow_idle_timeout=0.1,
            enabled=True,
        )

        # 1. Test signature detection helper
        pdf_header = b"%PDF-1.7\r\n1 0 obj\r\n<<...>>"
        tname, ext = detect_file_type(pdf_header)
        assert tname == "PDF Document"
        assert ext == "pdf"

        exe_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00"
        tname_exe, ext_exe = detect_file_type(exe_header)
        assert tname_exe == "PE Executable/DLL"
        assert ext_exe == "exe"

        # 2. Test stream reassembly and extraction
        flow_key = "tcp:10.0.0.1:4444<->192.168.1.50:80"
        payload_chunk1 = b"%PDF-1.7\r\nstream data chunk one\r\n"
        payload_chunk2 = b"stream data chunk two %%EOF\r\n"

        extractor.observe(flow_key, "10.0.0.1", "192.168.1.50", "tcp", payload_chunk1)
        extractor.observe(flow_key, "10.0.0.1", "192.168.1.50", "tcp", payload_chunk2)

        # Force flush all flows
        extracted_files = extractor.flush_all()
        assert len(extracted_files) == 1
        meta = extracted_files[0]
        assert meta["file_type"] == "PDF Document"
        assert meta["file_ext"] == "pdf"
        assert os.path.exists(meta["file_path"])

        with open(meta["file_path"], "rb") as f:
            content = f.read()
        assert content == payload_chunk1 + payload_chunk2


def test_stateful_flowbits_chaining():
    tracker = FlowBitTracker()
    engine = SignatureEngine(flowbit_tracker=tracker)

    # Rule 1: Sets flowbit "malware.stage1" when payload has "BEACON_INIT"
    rule_stage1 = SignatureRule(
        id="TEST-STAGE1",
        name="Stage 1 Beacon Initialized",
        severity="medium",
        match=SignatureMatch(
            protocol="tcp",
            destination_port=80,
            content="BEACON_INIT",
            flowbits_set="malware.stage1",
        )
    )

    # Rule 2: Only matches if flowbit "malware.stage1" is set on this flow
    rule_stage2 = SignatureRule(
        id="TEST-STAGE2",
        name="Stage 2 Code Execution Triggered",
        severity="critical",
        match=SignatureMatch(
            protocol="tcp",
            destination_port=80,
            content="EXEC_PAYLOAD",
            flowbits_isset="malware.stage1",
            flowbits_set="malware.compromised",
        )
    )

    flow_A_pkt_stage2_early = PacketRecord(
        timestamp=1.0,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        protocol="tcp",
        src_port=50001,
        dst_port=80,
        payload_text="EXEC_PAYLOAD",
    )

    flow_A_pkt_stage1 = PacketRecord(
        timestamp=2.0,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        protocol="tcp",
        src_port=50001,
        dst_port=80,
        payload_text="BEACON_INIT",
    )

    flow_A_pkt_stage2 = PacketRecord(
        timestamp=3.0,
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        protocol="tcp",
        src_port=50001,
        dst_port=80,
        payload_text="EXEC_PAYLOAD",
    )

    # Packet on completely different Flow B with same Stage 2 payload
    flow_B_pkt_stage2 = PacketRecord(
        timestamp=4.0,
        src_ip="192.168.1.99",
        dst_ip="10.0.0.5",
        protocol="tcp",
        src_port=60002,
        dst_port=80,
        payload_text="EXEC_PAYLOAD",
    )

    # 1. Stage 2 packet arriving BEFORE Stage 1 must NOT match
    assert not engine.matches(rule_stage2, flow_A_pkt_stage2_early)

    # 2. Stage 1 packet matches and sets bit
    assert engine.matches(rule_stage1, flow_A_pkt_stage1)
    engine.apply_flowbits(rule_stage1, flow_A_pkt_stage1)

    assert tracker.isset_bit(flow_A_pkt_stage1.flow_key, "malware.stage1")

    # 3. Stage 2 packet on Flow A NOW matches!
    assert engine.matches(rule_stage2, flow_A_pkt_stage2)
    engine.apply_flowbits(rule_stage2, flow_A_pkt_stage2)
    assert tracker.isset_bit(flow_A_pkt_stage2.flow_key, "malware.compromised")

    # 4. Stage 2 packet on Flow B must NOT match (isolation between flows)
    assert not engine.matches(rule_stage2, flow_B_pkt_stage2)
