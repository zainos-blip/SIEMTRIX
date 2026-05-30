#!/usr/bin/env python3
"""
Zeek HEC Forwarder - Sends static_openmodsim.log lines to Splunk HEC
"""
import time
import requests
import json
import os
import sys
import urllib3

# Suppress insecure HTTPS warnings (only if you use self-signed certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEC_URL = "https://{INDEXER_IP}:{INDEXER_PORT}/services/collector"
HEC_TOKEN = "eb36eeec-abfb-4f00-980c-bbd4bf166b54"
LOG_FILE = "/opt/zeek/logs/current/static_openmodsim.log"

# Throttle: seconds per event
SEND_DELAY = 0.5

def send_to_hec(line):
    """Send a single line (already a Zeek log line) to Splunk HEC."""
    headers = {"Authorization": f"Splunk {HEC_TOKEN}", "Content-Type": "application/json"}
    # Send the raw line as the event; Splunk will parse it as a single event.
    payload = {"event": line.strip(), "sourcetype": "zeek:openmodsim", "index": "ot_ids_behavior", "host": "kali"}
    try:
        response = requests.post(HEC_URL, json=payload, headers=headers, verify=False, timeout=2)
        if response.status_code in (200, 201):
            print(f"✓ Zeek sent: {line.strip()[:50]}...")
        else:
            print(f"✗ Zeek HEC error {response.status_code}: {response.text}")
    except Exception as e:
        print(f"✗ Zeek send failed: {e}")
    time.sleep(SEND_DELAY)

def tail_with_reopen():
    """Tail the log file, handling rotation (inode change) and reopening."""
    last_ino = 0
    f = None
    while True:
        try:
            # Check if file exists
            if not os.path.exists(LOG_FILE):
                time.sleep(1)
                continue

            # Get current inode
            current_ino = os.stat(LOG_FILE).st_ino

            # If inode changed (log rotated) or first open, reopen
            if current_ino != last_ino or f is None:
                if f:
                    f.close()
                f = open(LOG_FILE, 'r')
                f.seek(0, os.SEEK_END)   # Start from end – only new lines
                last_ino = current_ino
                print(f"Zeek file reopened. New inode: {current_ino}")

            # Read one line at a time
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            send_to_hec(line)

        except KeyboardInterrupt:
            if f:
                f.close()
            sys.exit(0)
        except Exception as e:
            print(f"Zeek forwarder error: {e}")
            if f:
                f.close()
                f = None
            time.sleep(1)

if __name__ == "__main__":
    # Ensure the log file exists (create empty if missing)
    if not os.path.exists(LOG_FILE):
        try:
            open(LOG_FILE, 'a').close()
            print(f"Created empty {LOG_FILE}")
        except Exception as e:
            print(f"Error creating {LOG_FILE}: {e}")
            sys.exit(1)

    print(f"Zeek HEC forwarder started. Monitoring {LOG_FILE} (delay {SEND_DELAY}s per event)")
    tail_with_reopen()
