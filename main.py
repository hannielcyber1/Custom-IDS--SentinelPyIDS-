#!/usr/bin/env python3
"""
SentinelPy IDS Main Launcher
Usage:
  python main.py validate
  python main.py interfaces
  python main.py run
  python main.py replay --pcap tests/pcaps/tcp_port_scan.pcap
  python main.py alerts
  python main.py status
"""

import sys
import os
import warnings
import logging

# Suppress harmless third-party deprecation and scapy runtime noise before scapy loads
warnings.filterwarnings("ignore", category=DeprecationWarning)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from sentinelpy.cli import main

if __name__ == "__main__":
    main()
