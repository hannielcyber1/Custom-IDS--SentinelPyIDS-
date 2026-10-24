"""
SentinelPy IDS - Command Line Interface
Implements operational subcommands: validate, interfaces, run, replay, alerts, status.
"""

import argparse
import sys
import os
import yaml
import time
from typing import Dict, Any

from sentinelpy import __version__
from sentinelpy.rules.loader import RuleCatalog, RuleValidationError
from sentinelpy.rules.snort_importer import import_snort_rules
from sentinelpy.alerts.webhook_notifier import WebhookNotifier
from sentinelpy.enrichment.geoip import GeoIPLookup
from sentinelpy.enrichment.ip_reputation import IPReputationChecker
from sentinelpy.ips.blocker import IPSBlocker
from sentinelpy.extraction.file_extractor import FileExtractor
from sentinelpy.storage.database import DatabaseStorage
from sentinelpy.storage.jsonl_writer import JsonlWriter
from sentinelpy.alerts.email_notifier import EmailNotifier
from sentinelpy.alerts.manager import AlertManager, TermColors
from sentinelpy.monitoring.metrics import MetricsCollector
from sentinelpy.core.flow_tracker import FlowTracker
from sentinelpy.engine import SentinelEngine
from sentinelpy.capture.live import LiveCapture
from sentinelpy.capture.replay import PcapReplayer

import warnings
import logging

# Suppress harmless third-party deprecation noise from Scapy/Cryptography
warnings.filterwarnings("ignore", category=DeprecationWarning)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

BANNER = rf"""{TermColors.CYAN}{TermColors.BOLD}
  ____             _   _            _ _____         _____ _____   _____ 
 / ___|  ___ _ __ | |_(_)_ __   ___| |  __ \       |_   _|  __ \ / ____|
 \___ \ / _ \ '_ \| __| | '_ \ / _ \ | |__) | _   _  | | | |  | | (___  
  ___) |  __/ | | | |_| | | | |  __/ |  ___/ | | | | | | | |  | |\___ \ 
 |____/ \___|_| |_|\__|_|_| |_|\___|_|_|     | |_| |_| |_| |__| |____) |
                                              \__, |                    
                                              |___/  Version {__version__}
                                                     Built by hannielcyber1
{TermColors.RESET}"""

def load_config(config_path: str = "config/ids.yaml") -> Dict[str, Any]:
    # Prefer local uncommitted overrides if present
    if config_path == "config/ids.yaml" and os.path.exists("config/local_ids.yaml"):
        config_path = "config/local_ids.yaml"
    if not os.path.exists(config_path):
        return {}
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def cmd_validate(args):
    print(BANNER)
    config_path = args.config
    print(f"{TermColors.CYAN}[*] Validating SentinelPy configuration: {config_path}{TermColors.RESET}")
    config = load_config(config_path)
    
    sig_dir = config.get("rules", {}).get("signatures_dir", "rules/signatures")
    behav_dir = config.get("rules", {}).get("behavioral_dir", "rules/behavioral")
    
    catalog = RuleCatalog()
    try:
        sig_count, behav_count = catalog.load_from_directory(sig_dir, behav_dir)
        print(f"{TermColors.GREEN}[+] Configuration syntax is valid.{TermColors.RESET}")
        print(f"{TermColors.GREEN}[+] Loaded {sig_count} Signature Rules.{TermColors.RESET}")
        print(f"{TermColors.GREEN}[+] Loaded {behav_count} Behavioral Rules.{TermColors.RESET}")
    except RuleValidationError as e:
        print(f"{TermColors.RED}[!] Rule Validation Error: {e}{TermColors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{TermColors.RED}[!] Error loading rules: {e}{TermColors.RESET}")
        sys.exit(1)

def cmd_interfaces(args):
    print(BANNER)
    print(f"{TermColors.CYAN}[*] Detecting available network interfaces...{TermColors.RESET}\n")
    ifaces = LiveCapture.get_interfaces()
    if not ifaces:
        print(f"{TermColors.YELLOW}[!] No network interfaces returned. Ensure Npcap / WinPcap is installed.{TermColors.RESET}")
        return

    for idx, iface in enumerate(ifaces, 1):
        print(f"  {TermColors.GREEN}{idx}.{TermColors.RESET} {iface}")
    print(f"\n{TermColors.CYAN}[*] To run on a specific interface, use: sentinelpy run --interface <name>{TermColors.RESET}")

def cmd_alerts(args):
    print(BANNER)
    config = load_config(args.config)
    db_path = config.get("storage", {}).get("database_path", "sentinelpy.db")
    db = DatabaseStorage(db_path)
    
    alerts = db.get_recent_alerts(limit=args.limit)
    print(f"{TermColors.CYAN}[*] Displaying recent alerts from {db_path} (Limit: {args.limit}):{TermColors.RESET}\n")
    if not alerts:
        print(f"{TermColors.YELLOW}No alerts recorded in database.{TermColors.RESET}")
        return

    for a in alerts:
        sev = a["severity"].upper()
        color = TermColors.RED if sev in ("HIGH", "CRITICAL") else (TermColors.YELLOW if sev == "MEDIUM" else TermColors.CYAN)
        print(f"{color}[{a['timestamp']}] [{sev}] {a['rule_name']} ({a['rule_id']}){TermColors.RESET}")
        print(f"    Source: {a['src_ip']} -> Target: {a['dst_ip']} | Proto: {a['protocol'].upper()}")
        print(f"    Evidence: {a['evidence']}\n")

def cmd_status(args):
    print(BANNER)
    config = load_config(args.config)
    db_path = config.get("storage", {}).get("database_path", "sentinelpy.db")
    jsonl_path = config.get("storage", {}).get("jsonl_path", "alerts.jsonl")
    
    total_alerts = 0
    if os.path.exists(db_path):
        db = DatabaseStorage(db_path)
        total_alerts = db.get_alert_count()

    print(f"{TermColors.CYAN}{TermColors.BOLD}[*] SentinelPy Engine Health & Environment Status:{TermColors.RESET}")
    print(f"  - Database: {db_path} ({'Active' if os.path.exists(db_path) else 'Pending creation'})")
    print(f"  - Total Historical Alerts: {total_alerts}")
    print(f"  - JSONL Stream Path: {jsonl_path}")
    print(f"  - Python Version: {sys.version.split()[0]}")

def cmd_replay(args):
    print(BANNER)
    pcap_path = args.pcap
    if not os.path.exists(pcap_path):
        print(f"{TermColors.RED}[!] PCAP file not found: {pcap_path}{TermColors.RESET}")
        sys.exit(1)

    config = load_config(args.config)
    catalog = RuleCatalog()
    sig_dir = config.get("rules", {}).get("signatures_dir", "rules/signatures")
    behav_dir = config.get("rules", {}).get("behavioral_dir", "rules/behavioral")
    catalog.load_from_directory(sig_dir, behav_dir)

    metrics = MetricsCollector()
    db = DatabaseStorage(config.get("storage", {}).get("database_path", "sentinelpy.db"))
    writer = JsonlWriter(
        jsonl_path=config.get("storage", {}).get("jsonl_path", "alerts.jsonl"),
        text_log_path=config.get("storage", {}).get("text_log_path", "ids_alerts.log")
    )
    # In replay mode, disable email sending unless explicitly enabled
    email_config = config.get("email_alerts", {}).copy()
    email_config["enabled"] = False
    notifier = EmailNotifier(email_config)
    
    alert_mgr = AlertManager(
        db_storage=db,
        jsonl_writer=writer,
        email_notifier=notifier,
        cooldown_seconds=0.0, # No cooldown in offline replay for complete deterministic validation
        webhook_notifier=WebhookNotifier({}),  # disabled by default in replay
    )
    
    engine = SentinelEngine(catalog, alert_mgr, metrics)
    replayer = PcapReplayer(pcap_path, metrics)

    print(f"{TermColors.CYAN}[*] Replaying PCAP capture: {pcap_path}{TermColors.RESET}")
    t0 = time.time()
    packet_count = replayer.replay(engine.process_packet, max_packets=args.max_packets)
    duration = max(0.001, time.time() - t0)

    stats = metrics.get_summary(active_flows=engine.flow_tracker.active_flows_count())
    print(f"\n{TermColors.GREEN}{TermColors.BOLD}[+] Replay Completed in {round(duration, 3)}s{TermColors.RESET}")
    print(f"    - Packets Processed: {stats['packets_processed']}")
    print(f"    - Alerts Generated: {stats['alerts_generated']}")
    print(f"    - Throughput: {stats['packets_per_second']} pps")
    print(f"    - Avg Detection Latency: {stats['avg_detection_latency_ms']} ms/pkt")

def cmd_run(args):
    print(BANNER)
    config = load_config(args.config)
    sensor_id = config.get("sensor_id", "sentinelpy-lab")

    catalog = RuleCatalog()
    sig_dir = config.get("rules", {}).get("signatures_dir", "rules/signatures")
    behav_dir = config.get("rules", {}).get("behavioral_dir", "rules/behavioral")
    sig_count, behav_count = catalog.load_from_directory(sig_dir, behav_dir)

    metrics = MetricsCollector()
    db = DatabaseStorage(config.get("storage", {}).get("database_path", "sentinelpy.db"))
    writer = JsonlWriter(
        jsonl_path=config.get("storage", {}).get("jsonl_path", "alerts.jsonl"),
        text_log_path=config.get("storage", {}).get("text_log_path", "ids_alerts.log")
    )
    email_cfg = config.get("email_alerts", {})
    notifier = EmailNotifier(email_cfg)

    alert_mgr = AlertManager(
        db_storage=db,
        jsonl_writer=writer,
        email_notifier=notifier,
        cooldown_seconds=email_cfg.get("cooldown_seconds", 60.0),
        sensor_name=sensor_id,
        webhook_notifier=WebhookNotifier(config.get("webhook", {})),
    )

    flow_cfg = config.get("flow_tracker", {})
    flow_tracker = FlowTracker(
        idle_timeout=flow_cfg.get("idle_timeout_seconds", 120.0),
        max_flows=flow_cfg.get("max_tracked_flows", 10000)
    )

    # GeoIP enrichment
    geoip_cfg = config.get("geoip", {})
    geoip = GeoIPLookup(enabled=geoip_cfg.get("enabled", False)) if geoip_cfg.get("enabled") else None

    # IP Reputation / Blocklist
    rep_cfg = config.get("ip_reputation", {})
    ip_rep = None
    if rep_cfg.get("enabled", False):
        ip_rep = IPReputationChecker(blocklist_path=rep_cfg.get("blocklist_path"))

    # IPS Active Blocking
    ips_cfg = config.get("ips", {})
    ips_blocker = None
    if ips_cfg.get("enabled", False):
        ips_blocker = IPSBlocker(
            db_path=config.get("storage", {}).get("database_path", "sentinelpy.db"),
            block_duration_minutes=ips_cfg.get("block_duration_minutes", 60),
            auto_block_severities=ips_cfg.get("auto_block_severities", ["critical", "high"]),
            enabled=True,
            dry_run=ips_cfg.get("dry_run", False),
        )
        ips_blocker.start()

    # File Extraction
    ext_cfg = config.get("file_extraction", {})
    file_extractor = None
    if ext_cfg.get("enabled", False):
        file_extractor = FileExtractor(
            output_dir=ext_cfg.get("output_dir", "extractions"),
            max_file_size_bytes=ext_cfg.get("max_file_size_mb", 10) * 1024 * 1024,
            enabled=True,
        )

    engine = SentinelEngine(
        catalog, alert_mgr, metrics,
        flow_tracker=flow_tracker,
        sensor_id=sensor_id,
        geoip=geoip,
        ip_reputation=ip_rep,
        ips_blocker=ips_blocker,
        file_extractor=file_extractor,
    )
    capture = LiveCapture(interface=args.interface, metrics=metrics)

    print(f"{TermColors.CYAN}{TermColors.BOLD}[*] SentinelPy IDS Active - Monitoring Network Traffic{TermColors.RESET}")
    print(f"    - Sensor ID: {sensor_id}")
    print(f"    - Interface: {args.interface or 'Default System Interface'}")
    print(f"    - Active Rules: {sig_count} Signatures | {behav_count} Behavioral Models")
    print(f"    - Alerts Database: {db.db_path} | Streaming Log: {writer.jsonl_path}")
    print(f"{TermColors.CYAN}[*] Press Ctrl+C to stop capture and display operational metrics.{TermColors.RESET}\n")

    # Send startup alert if configured
    if email_cfg.get("notify_on_start_stop", True):
        notifier.send_notification(
            "SentinelPy Started",
            f"SentinelPy IDS has started monitoring on interface '{args.interface or 'Default'}'. Rules active: {sig_count + behav_count}."
        )

    try:
        capture.start(engine.process_packet)
    except PermissionError:
        print(f"\n{TermColors.RED}{TermColors.BOLD}[ERROR] Permission denied: You must run this command from an elevated prompt (Run as Administrator).{TermColors.RESET}")
    except KeyboardInterrupt:
        print(f"\n{TermColors.YELLOW}[*] Stopping SentinelPy IDS capture...{TermColors.RESET}")
        if email_cfg.get("notify_on_start_stop", True):
            notifier.send_notification(
                "SentinelPy Stopped",
                "SentinelPy IDS monitoring session was cleanly terminated by administrator.",
                sync=True
            )
        stats = metrics.get_summary(active_flows=flow_tracker.active_flows_count())
        print(f"\n{TermColors.GREEN}{TermColors.BOLD}[+] Operational Session Summary:{TermColors.RESET}")
        print(f"    - Uptime: {stats['uptime_seconds']}s")
        print(f"    - Packets Processed: {stats['packets_processed']}")
        print(f"    - Total Alerts: {stats['alerts_generated']}")
        print(f"    - Active Tracked Flows: {stats['active_flows']}")
        print(f"    - Avg Latency: {stats['avg_detection_latency_ms']} ms/pkt")
        print(f"{TermColors.CYAN}[*] Session closed cleanly.{TermColors.RESET}")
    finally:
        engine.stop()

def cmd_update_blocklist(args):
    print(BANNER)
    config = load_config(args.config)
    rep_cfg = config.get("ip_reputation", {})
    url       = args.url or rep_cfg.get("blocklist_url", IPReputationChecker.__init__.__defaults__[0] if False else "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt")
    save_path = args.output or rep_cfg.get("blocklist_path", "rules/blocklist/feodo_blocklist.txt")

    print(f"{TermColors.CYAN}[*] Downloading IP blocklist from:{TermColors.RESET}")
    print(f"    {url}")
    print(f"{TermColors.CYAN}[*] Saving to: {save_path}{TermColors.RESET}\n")

    checker = IPReputationChecker()
    try:
        count = checker.download_blocklist(url=url, save_path=save_path)
        print(f"{TermColors.GREEN}{TermColors.BOLD}[+] Blocklist updated successfully!{TermColors.RESET}")
        print(f"    - IPs loaded: {TermColors.GREEN}{count}{TermColors.RESET}")
        print(f"    - Saved to  : {save_path}")
        print(f"\n{TermColors.CYAN}[*] Enable IP reputation in config/ids.yaml:{TermColors.RESET}")
        print(f"    ip_reputation:")
        print(f"      enabled: true")
        print(f"      blocklist_path: {save_path}")
    except Exception as e:
        print(f"{TermColors.RED}[!] Blocklist download failed: {e}{TermColors.RESET}")
        sys.exit(1)


def cmd_import_snort(args):
    print(BANNER)
    rules_path  = args.rules
    output_path = args.output
    config      = load_config(args.config)

    print(f"{TermColors.CYAN}[*] Importing Snort rules from: {rules_path}{TermColors.RESET}")
    print(f"{TermColors.CYAN}[*] Output target: {output_path}{TermColors.RESET}\n")

    try:
        result = import_snort_rules(rules_path, output_path)
    except FileNotFoundError as e:
        print(f"{TermColors.RED}[!] {e}{TermColors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{TermColors.RED}[!] Import failed: {e}{TermColors.RESET}")
        sys.exit(1)

    # Print per-rule summary with colour
    for rd in result.converted:
        sev = rd["severity"].upper()
        col = (TermColors.RED   if sev in ("CRITICAL", "HIGH") else
               TermColors.YELLOW if sev == "MEDIUM" else
               TermColors.CYAN)
        print(f"  {col}[+] {rd['id']} | {sev:8s} | {rd['name'][:70]}{TermColors.RESET}")

    print()
    if result.warnings:
        for w in result.warnings:
            print(f"{TermColors.YELLOW}[!] {w}{TermColors.RESET}")
        print()

    if result.skipped:
        print(f"{TermColors.YELLOW}[!] Skipped {result.skipped_count} rule(s) (unsupported/malformed):{TermColors.RESET}")
        for s in result.skipped[:10]:
            print(f"       {s}")
        if result.skipped_count > 10:
            print(f"       ... and {result.skipped_count - 10} more.")
        print()

    print(f"{TermColors.GREEN}{TermColors.BOLD}[+] Import complete!{TermColors.RESET}")
    print(f"    - Converted : {TermColors.GREEN}{result.converted_count}{TermColors.RESET} rules")
    print(f"    - Skipped   : {TermColors.YELLOW}{result.skipped_count}{TermColors.RESET} rules")
    print(f"    - Output    : {output_path}\n")

    # Validate the output file immediately
    print(f"{TermColors.CYAN}[*] Validating imported rule file...{TermColors.RESET}")
    catalog = RuleCatalog()
    try:
        sig_dir  = config.get("rules", {}).get("signatures_dir", "rules/signatures")
        behav_dir = config.get("rules", {}).get("behavioral_dir", "rules/behavioral")
        sig_count, behav_count = catalog.load_from_directory(sig_dir, behav_dir)
        print(f"{TermColors.GREEN}[+] Validation passed — Total active signature rules: {sig_count}{TermColors.RESET}")
    except RuleValidationError as e:
        print(f"{TermColors.RED}[!] Validation error after import: {e}{TermColors.RESET}")
        sys.exit(1)


def cmd_ips_list(args):
    print(BANNER)
    config = load_config(args.config)
    db_path = config.get("storage", {}).get("database_path", "sentinelpy.db")
    blocker = IPSBlocker(db_path=db_path, enabled=True)
    blocks = blocker.list_blocks()
    print(f"{TermColors.CYAN}[*] Active IPS Firewall Blocks ({len(blocks)} recorded):{TermColors.RESET}\n")
    if not blocks:
        print(f"{TermColors.YELLOW}No active firewall blocks recorded.{TermColors.RESET}")
        return
    for b in blocks:
        print(f"  {TermColors.RED}[BLOCKED]{TermColors.RESET} {TermColors.BOLD}{b['ip']:16s}{TermColors.RESET} | Reason: {b.get('reason', '')} (Rule: {b.get('rule_id', 'N/A')})")
        print(f"    Blocked At: {b['blocked_at']} | Expires: {b['expires_at']}\n")


def cmd_ips_unblock(args):
    print(BANNER)
    config = load_config(args.config)
    db_path = config.get("storage", {}).get("database_path", "sentinelpy.db")
    dry_run = config.get("ips", {}).get("dry_run", False)
    blocker = IPSBlocker(db_path=db_path, enabled=True, dry_run=dry_run)
    ip = args.ip
    print(f"{TermColors.CYAN}[*] Removing IPS block for: {ip}{TermColors.RESET}")
    success = blocker.unblock(ip)
    if success:
        print(f"{TermColors.GREEN}[+] Successfully unblocked {ip}{TermColors.RESET}")
    else:
        print(f"{TermColors.YELLOW}[!] Could not unblock {ip} (or already unblocked){TermColors.RESET}")


def cmd_ips_clear(args):
    print(BANNER)
    config = load_config(args.config)
    db_path = config.get("storage", {}).get("database_path", "sentinelpy.db")
    dry_run = config.get("ips", {}).get("dry_run", False)
    blocker = IPSBlocker(db_path=db_path, enabled=True, dry_run=dry_run)
    print(f"{TermColors.CYAN}[*] Clearing all active IPS firewall blocks...{TermColors.RESET}")
    count = blocker.clear_all()
    print(f"{TermColors.GREEN}[+] Removed {count} active firewall block(s).{TermColors.RESET}")


def main():
    parser = argparse.ArgumentParser(
        prog="sentinelpy",
        description="SentinelPy IDS - Modular Network Intrusion Detection System"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="subcommand", help="Operational Subcommands")

    # validate
    p_val = subparsers.add_parser("validate", help="Validate configuration and rules")
    p_val.add_argument("--config", default="config/ids.yaml", help="Path to ids.yaml configuration")
    p_val.set_defaults(func=cmd_validate)

    # interfaces
    p_if = subparsers.add_parser("interfaces", help="List available network interfaces")
    p_if.set_defaults(func=cmd_interfaces)

    # run
    p_run = subparsers.add_parser("run", help="Monitor live authorized network interface")
    p_run.add_argument("--interface", "-i", default=None, help="Interface name or IP to capture")
    p_run.add_argument("--config", default="config/ids.yaml", help="Path to ids.yaml configuration")
    p_run.set_defaults(func=cmd_run)

    # replay
    p_rep = subparsers.add_parser("replay", help="Replay and analyze an offline PCAP capture")
    p_rep.add_argument("--pcap", required=True, help="Path to PCAP file")
    p_rep.add_argument("--max-packets", type=int, default=None, help="Max packets to replay")
    p_rep.add_argument("--config", default="config/ids.yaml", help="Path to ids.yaml configuration")
    p_rep.set_defaults(func=cmd_replay)

    # alerts
    p_alt = subparsers.add_parser("alerts", help="Display recent historical alerts from SQLite")
    p_alt.add_argument("--limit", type=int, default=50, help="Number of recent alerts to retrieve")
    p_alt.add_argument("--config", default="config/ids.yaml", help="Path to ids.yaml configuration")
    p_alt.set_defaults(func=cmd_alerts)

    # status
    p_stat = subparsers.add_parser("status", help="Display engine health and storage status")
    p_stat.add_argument("--config", default="config/ids.yaml", help="Path to ids.yaml configuration")
    p_stat.set_defaults(func=cmd_status)

    # import-snort
    p_snort = subparsers.add_parser("import-snort", help="Import & convert Snort .rules file to SentinelPy YAML")
    p_snort.add_argument("--rules", required=True, help="Path to input .rules file (Snort/Suricata format)")
    p_snort.add_argument(
        "--output",
        default="rules/signatures/snort_community.yaml",
        help="Path to write converted YAML rules (default: rules/signatures/snort_community.yaml)",
    )
    p_snort.add_argument("--config", default="config/ids.yaml", help="Path to ids.yaml configuration")
    p_snort.set_defaults(func=cmd_import_snort)

    # update-blocklist
    p_bl = subparsers.add_parser("update-blocklist", help="Download latest known-malicious IP blocklist")
    p_bl.add_argument("--url", default=None, help="Blocklist URL (overrides config)")
    p_bl.add_argument("--output", default=None, help="Save path for the downloaded list (overrides config)")
    p_bl.add_argument("--config", default="config/ids.yaml", help="Path to ids.yaml configuration")
    p_bl.set_defaults(func=cmd_update_blocklist)

    # ips-list
    p_ilist = subparsers.add_parser("ips-list", help="List active IPS firewall blocks")
    p_ilist.add_argument("--config", default="config/ids.yaml", help="Path to ids.yaml configuration")
    p_ilist.set_defaults(func=cmd_ips_list)

    # ips-unblock
    p_iunblock = subparsers.add_parser("ips-unblock", help="Manually unblock an IP address from firewall")
    p_iunblock.add_argument("--ip", required=True, help="IP address to unblock")
    p_iunblock.add_argument("--config", default="config/ids.yaml", help="Path to ids.yaml configuration")
    p_iunblock.set_defaults(func=cmd_ips_unblock)

    # ips-clear
    p_iclear = subparsers.add_parser("ips-clear", help="Clear all active IPS firewall blocks")
    p_iclear.add_argument("--config", default="config/ids.yaml", help="Path to ids.yaml configuration")
    p_iclear.set_defaults(func=cmd_ips_clear)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(0)

    args.func(args)

if __name__ == "__main__":
    main()
