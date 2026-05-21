#!/usr/bin/env python3
"""
Suricata OT Receiver - Polling Mode (works with Suricata's batch behaviour)
"""
import socket
import os
import sys
import time
import signal
import struct
import subprocess
import threading
import json
from datetime import datetime

SURICATA_PORT = 5555
PCAP_DIR = "/var/log/suricata/ot_input"
LOG_DIR = "/var/log/suricata"
RULES_FILE = "/etc/suricata/rules/ot-security.rules"

os.makedirs(PCAP_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

class SuricataReceiver:
    def __init__(self):
        self.running = True
        self.packet_count = 0
        self.alert_count = 0
        self.pcap_file = None
        self.pcap_handle = None
        self.suricata_process = None
        self.start_time = time.time()
        self.last_processed_size = 0
        
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        self.create_pcap()
        self.start_alert_monitor()
        self.start_suricata_looper()
        self.print_banner()

    def print_banner(self):
        print(f"╔{'═'*60}╗")
        print(f"║{'SURICATA RECEIVER (POLLING MODE)':^60}║")
        print(f"╠{'═'*60}╣")
        print(f"║ UDP port: {SURICATA_PORT:<53}║")
        print(f"║ PCAP dir: {PCAP_DIR:<53}║")
        print(f"║ Log dir: {LOG_DIR:<53}║")
        print(f"║ Rules: {RULES_FILE:<53}║")
        print(f"║ Polls PCAP every 2 seconds, runs Suricata on new data{' ' * 10}║")
        print(f"╚{'═'*60}╝")

    def create_pcap(self):
        if self.pcap_handle:
            self.pcap_handle.close()
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.pcap_file = os.path.join(PCAP_DIR, f"suricata_input_{timestamp}.pcap")
        self.pcap_handle = open(self.pcap_file, 'wb')
        
        # PCAP global header
        pcap_hdr = struct.pack('=IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        self.pcap_handle.write(pcap_hdr)
        self.pcap_handle.flush()
        
        # Symlink for Suricata
        current_link = os.path.join(PCAP_DIR, "current.pcap")
        if os.path.exists(current_link):
            os.unlink(current_link)
        try:
            os.symlink(self.pcap_file, current_link)
        except:
            pass
        
        print(f"[+] New PCAP: {self.pcap_file}")
        self.last_processed_size = 0

    def write_packet(self, data):
        if not self.pcap_handle:
            return
        ts_sec = int(time.time())
        ts_usec = int((time.time() - ts_sec) * 1000000)
        incl_len = len(data)
        pkt_hdr = struct.pack('=IIII', ts_sec, ts_usec, incl_len, incl_len)
        try:
            self.pcap_handle.write(pkt_hdr)
            self.pcap_handle.write(data)
            self.pcap_handle.flush()
        except Exception as e:
            print(f"[-] Write error: {e}")

    def run_suricata_once(self):
        """Run Suricata on the current PCAP file (will exit after reading it)"""
        current_pcap = os.path.join(PCAP_DIR, "current.pcap")
        if not os.path.exists(current_pcap):
            return
        
        # Only run if file has grown since last run
        current_size = os.path.getsize(current_pcap)
        if current_size <= self.last_processed_size:
            return
        self.last_processed_size = current_size
        
        cmd = [
            "suricata", "-c", "/etc/suricata/suricata.yaml",
            "-r", current_pcap,
            "-l", LOG_DIR,
            "-S", RULES_FILE,
            "-k", "none"   # disable checksum validation for speed
        ]
        
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            # Suricata exit code 0 is normal (processed file)
            if proc.returncode != 0:
                print(f"[-] Suricata error (code {proc.returncode})")
                if proc.stderr:
                    print(proc.stderr[:500])
            else:
                # Count alerts from eve.json
                eve_file = os.path.join(LOG_DIR, "eve.json")
                if os.path.exists(eve_file):
                    with open(eve_file, 'r') as f:
                        new_alerts = sum(1 for line in f if '"alert"' in line)
                    if new_alerts > self.alert_count:
                        print(f"[+] Suricata processed {current_size} bytes, {new_alerts - self.alert_count} new alerts")
                        self.alert_count = new_alerts
        except subprocess.TimeoutExpired:
            print("[-] Suricata timed out")
        except Exception as e:
            print(f"[-] Suricata exception: {e}")

    def start_suricata_looper(self):
        """Background thread that runs Suricata every 2 seconds on the growing PCAP"""
        def looper():
            while self.running:
                self.run_suricata_once()
                time.sleep(2)
        t = threading.Thread(target=looper, daemon=True)
        t.start()
        print("[+] Suricata polling thread started (every 2 seconds)")

    def start_alert_monitor(self):
        """Monitor eve.json for new alerts and print them"""
        def monitor():
            last_pos = 0
            while self.running:
                try:
                    eve_file = os.path.join(LOG_DIR, "eve.json")
                    if os.path.exists(eve_file):
                        with open(eve_file, 'r') as f:
                            f.seek(last_pos)
                            for line in f:
                                try:
                                    ev = json.loads(line)
                                    if 'alert' in ev:
                                        print(f"\n⚠ ALERT: {ev['alert']['signature']}")
                                        print(f"   src: {ev.get('src_ip','?')}:{ev.get('src_port','?')}")
                                        print(f"   dst: {ev.get('dest_ip','?')}:{ev.get('dest_port','?')}")
                                except:
                                    pass
                            last_pos = f.tell()
                except:
                    pass
                time.sleep(1)
        threading.Thread(target=monitor, daemon=True).start()
        print("[+] Alert monitor started")

    def signal_handler(self, sig, frame):
        print("\n[⏹] Shutting down...")
        self.running = False
        if self.pcap_handle:
            self.pcap_handle.close()
        elapsed = time.time() - self.start_time
        print(f"[+] Packets: {self.packet_count}, Alerts: {self.alert_count}, {self.packet_count/elapsed:.1f} pkt/s")
        sys.exit(0)

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', SURICATA_PORT))
        sock.settimeout(1.0)
        print(f"[+] Listening on UDP {SURICATA_PORT}\n")
        
        while self.running:
            try:
                data, addr = sock.recvfrom(65535)
                self.packet_count += 1
                self.write_packet(data)
                if self.packet_count % 100 == 0:
                    elapsed = time.time() - self.start_time
                    print(f"[📊] {self.packet_count} pkts, {self.alert_count} alerts ({self.packet_count/elapsed:.1f}/s)")
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[-] Error: {e}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] Run as root (sudo)")
        sys.exit(1)
    receiver = SuricataReceiver()
    receiver.start()
