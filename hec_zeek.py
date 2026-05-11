#!/usr/bin/env python3
import time
import requests
import json
import os
import sys

HEC_URL = "https://100.103.226.100:8088/services/collector"
HEC_TOKEN = "eb36eeec-abfb-4f00-980c-bbd4bf166b54"
LOG_FILE = "/opt/zeek/logs/current/static_openmodsim.log"

# Throttle: seconds to wait after sending each event
SEND_DELAY = 0.5   # adjust as needed

def send_to_hec(line):
    headers = {"Authorization": f"Splunk {HEC_TOKEN}", "Content-Type": "application/json"}
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
    last_ino = 0
    while True:
        try:
            if not os.path.exists(LOG_FILE):
                time.sleep(1)
                continue
            current_ino = os.stat(LOG_FILE).st_ino
            if current_ino != last_ino:
                last_ino = current_ino
                f = open(LOG_FILE, 'r')
                f.seek(0, os.SEEK_END)
                print(f"Zeek file changed, reopening. New inode: {current_ino}")
        except Exception as e:
            print(f"Zeek stat error: {e}")
            time.sleep(1)
            continue
        try:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            send_to_hec(line)
        except Exception as e:
            f.close()
            last_ino = 0
            print(f"Zeek read error: {e}")
            time.sleep(1)

if __name__ == "__main__":
    if not os.path.exists(LOG_FILE):
        print(f"Error: {LOG_FILE} not found! Creating empty file.")
        open(LOG_FILE, 'a').close()
    print(f"Zeek HEC forwarder started. Monitoring {LOG_FILE} (delay {SEND_DELAY}s per event)")
    tail_with_reopen()
