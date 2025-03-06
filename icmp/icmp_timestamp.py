#!/usr/bin/env python3
"""
ICMP Timestamp Vulnerability Checker
Author: Vahe

This script checks if a target IP is vulnerable to an ICMP timestamp leak.
It sends an ICMP Timestamp Request (type 13) and, if a valid reply is received,
extracts the raw timestamp (milliseconds since midnight UTC) and converts it to a human-readable UTC time.

Usage:
    python icmp_timestamp.py <target_ip>
"""

import sys
import os
import ctypes
import warnings
import logging
from scapy.all import sr1, IP, ICMP
from datetime import datetime, timedelta, timezone

# Suppress DeprecationWarnings and Scapy warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def is_admin():
    try:
        return os.getuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

def parse_icmp_timestamp(ts):
    """
    Convert an ICMP timestamp (milliseconds since midnight UTC)
    to a human-readable date string.
    """
    # Convert milliseconds to seconds
    seconds_since_midnight = ts / 1000.0
    # Get today's UTC midnight time (timezone aware)
    base_time = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    # Add the seconds to midnight
    converted_time = base_time + timedelta(seconds=seconds_since_midnight)
    return converted_time.strftime("%Y-%m-%d %H:%M:%S (UTC)")

def icmp_timestamp_check(target_ip):
    packet = IP(dst=target_ip) / ICMP(type=13)
    reply = sr1(packet, timeout=5, verbose=0)

    if reply and ICMP in reply:
        try:
            ts_value = reply.ts_tx
        except AttributeError:
            print("[-] Reply does not contain a valid timestamp field.")
            return

        human_time = parse_icmp_timestamp(ts_value)
        print(f"[+] {target_ip} responded with timestamp. Vulnerable!")
        print(f"[*] Timestamp received: {ts_value}")
        print(f"[+] Detected system time: {human_time}")
    else:
        print("[-] No ICMP timestamp response received.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python icmp_timestamp.py <target_ip>")
        sys.exit(1)

    if not is_admin():
        print("[-] ERROR: This script requires Administrator privileges. Please run as administrator.")
        sys.exit(1)

    target_ip = sys.argv[1]
    icmp_timestamp_check(target_ip)
