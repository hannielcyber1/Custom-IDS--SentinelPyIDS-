import os
import pytest
from sentinelpy.rules.loader import RuleCatalog
from sentinelpy.storage.database import DatabaseStorage
from sentinelpy.storage.jsonl_writer import JsonlWriter
from sentinelpy.alerts.email_notifier import EmailNotifier
from sentinelpy.alerts.manager import AlertManager
from sentinelpy.monitoring.metrics import MetricsCollector
from sentinelpy.engine import SentinelEngine
from sentinelpy.capture.replay import PcapReplayer

@pytest.fixture
def test_env(tmp_path):
    db_file = str(tmp_path / "test_sentinelpy.db")
    jsonl_file = str(tmp_path / "test_alerts.jsonl")
    
    catalog = RuleCatalog()
    catalog.load_from_directory("rules/signatures", "rules/behavioral")
    
    metrics = MetricsCollector()
    db = DatabaseStorage(db_file)
    writer = JsonlWriter(jsonl_file)
    notifier = EmailNotifier({"enabled": False})
    
    alert_mgr = AlertManager(
        db_storage=db,
        jsonl_writer=writer,
        email_notifier=notifier,
        cooldown_seconds=0.0
    )
    
    engine = SentinelEngine(catalog, alert_mgr, metrics)
    return engine, db, metrics

def test_replay_port_scan_pcap(test_env):
    engine, db, metrics = test_env
    pcap_path = os.path.join("tests", "pcaps", "tcp_port_scan.pcap")
    assert os.path.exists(pcap_path)

    replayer = PcapReplayer(pcap_path, metrics)
    replayer.replay(engine.process_packet)

    alerts = db.get_recent_alerts(limit=10)
    # Must have detected SPY-B1001 (Port Scan)
    rule_ids = [a["rule_id"] for a in alerts]
    assert "SPY-B1001" in rule_ids

def test_replay_cleartext_creds_pcap(test_env):
    engine, db, metrics = test_env
    pcap_path = os.path.join("tests", "pcaps", "cleartext_creds.pcap")
    assert os.path.exists(pcap_path)

    replayer = PcapReplayer(pcap_path, metrics)
    replayer.replay(engine.process_packet)

    alerts = db.get_recent_alerts(limit=10)
    # Must have detected SPY-1003 (Plaintext Credentials)
    rule_ids = [a["rule_id"] for a in alerts]
    assert "SPY-1003" in rule_ids
