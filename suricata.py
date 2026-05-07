#!/usr/bin/env python3
"""
Integrated Suricata OT Receiver
Captures packets AND generates alerts in real-time
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

# Configuration
SURICATA_PORT = 5555
PCAP_DIR = "/var/log/suricata/ot_input"
LOG_DIR = "/var/log/suricata"

os.makedirs(PCAP_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

class IntegratedSuricataReceiver:
    def __init__(self):
        self.running = True
        self.packet_count = 0
        self.alert_count = 0
        self.pcap_file = None
        self.pcap_handle = None
        self.suricata_process = None
        self.last_rotation = time.time()
        self.start_time = time.time()
        
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        self.create_pcap()
        self.create_suricata_rules()
        self.start_suricata_analysis()
        self.start_alert_monitor()
        
        self.print_banner()

    def print_banner(self):
        print(f"╔{'═'*60}╗")
        print(f"║{'INTEGRATED SURICATA RECEIVER (CAPTURE + ANALYSIS)':^60}║")
        print(f"╠{'═'*60}╣")
        print(f"║ Listening on port: {SURICATA_PORT:<42}║")
        print(f"║ PCAP directory: {PCAP_DIR:<42}║")
        print(f"║ Log directory: {LOG_DIR:<42}║")
        print(f"╚{'═'*60}╝")

    def create_pcap(self):
        """Create a new PCAP file with proper header"""
        if self.pcap_handle:
            self.pcap_handle.close()
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.pcap_file = os.path.join(PCAP_DIR, f"suricata_input_{timestamp}.pcap")
        
        self.pcap_handle = open(self.pcap_file, 'wb')
        
        # Write PCAP global header
        pcap_hdr = struct.pack('=IHHiIII', 
            0xa1b2c3d4,  # magic number
            2, 4,        # version 2.4
            0,           # thiszone
            0,           # sigfigs
            65535,       # snaplen
            1            # network type (Ethernet)
        )
        self.pcap_handle.write(pcap_hdr)
        self.pcap_handle.flush()
        
        # Create symlink for Suricata to follow
        current_link = os.path.join(PCAP_DIR, "current.pcap")
        if os.path.exists(current_link):
            os.unlink(current_link)
        try:
            os.symlink(self.pcap_file, current_link)
        except:
            pass
        
        print(f"[+] New PCAP: {self.pcap_file}")

    def create_suricata_rules(self):
        """Create OT-specific Suricata rules"""
        rules_file = os.path.join(PCAP_DIR, "ot_suricata.rules")
        
        with open(rules_file, 'w') as f:
            f.write("""
# OT/ICS Suricata Rules

# Modbus detection
alert tcp any any -> any 502 (msg:"OT: Modbus Traffic Detected"; sid:1000001; rev:1;)
alert tcp any any -> any 502 (msg:"OT: Modbus Write Command"; content:"|00 00 00 00 00 06|"; depth:6; content:"|05 06|"; within:20; sid:1000002; rev:1;)
alert tcp any any -> any 502 (msg:"OT: Modbus Read Command"; content:"|00 00 00 00 00 06|"; depth:6; content:"|04|"; within:20; sid:1000003; rev:1;)
alert tcp any any -> any 502 (msg:"OT: Modbus Exception Response"; content:"|80|"; offset:7; within:1; sid:1000004; rev:1;)

# DNP3 detection
alert tcp any any -> any 20000 (msg:"OT: DNP3 Traffic Detected"; sid:1000005; rev:1;)

# S7Comm detection (Siemens)
alert tcp any any -> any 102 (msg:"OT: S7Comm Traffic Detected"; sid:1000006; rev:1;)

# OT Protocol misuse
alert tcp any any -> any 502 (msg:"OT: Modbus Function Code 90 - Illegal Function"; content:"|5a|"; offset:7; within:1; sid:1000007; rev:1;)

# Unusual connections
alert tcp $HOME_NET any -> $EXTERNAL_NET 502 (msg:"OT: OT Device Connecting to External Modbus"; sid:1000008; rev:1;)

# Scan detection
alert tcp any any -> $HOME_NET 502,20000,102 (msg:"OT: OT Port Scan Detected"; flags:S; threshold:type both, track by_src, count 5, seconds 10; sid:1000009; rev:1;)

# Custom PLC protocol (port 5800)
alert tcp any any -> 192.168.18.106 5800 (msg:"OT: PLC Command to OpenModsim"; sid:2000001; rev:1;)
alert tcp 172.20.96.57 any -> 192.168.18.106 5800 (msg:"OT: SCADA to PLC Normal Command"; dsize:12; sid:2000002; rev:1;)
alert tcp 192.168.18.106 5800 -> 172.20.96.57 any (msg:"OT: PLC Normal Response"; dsize:31; sid:2000003; rev:1;)
""")
        
        print(f"[+] Suricata rules created: {rules_file}")

    def start_suricata_analysis(self):
        """Start Suricata process to analyze the PCAP file"""
        rules_file = os.path.join(PCAP_DIR, "ot_suricata.rules")
        
        cmd = ["suricata", "-c", "/etc/suricata/suricata.yaml",
               "-r", os.path.join(PCAP_DIR, "current.pcap"),
               "-l", LOG_DIR,
               "-S", rules_file]
        
        self.suricata_process = subprocess.Popen(cmd, 
                                                stdout=subprocess.DEVNULL,
                                                stderr=subprocess.DEVNULL)
        
        print(f"[+] Suricata analyzer started (PID: {self.suricata_process.pid})")

    def start_alert_monitor(self):
        """Monitor Suricata alerts in real-time"""
        def monitor_alerts():
            last_position = 0
            
            while self.running:
                try:
                    eve_file = os.path.join(LOG_DIR, "eve.json")
                    if os.path.exists(eve_file):
                        with open(eve_file, 'r') as f:
                            f.seek(last_position)
                            for line in f:
                                try:
                                    event = json.loads(line.strip())
                                    if 'alert' in event:
                                        self.alert_count += 1
                                        print(f"\n{'⚠️'*60}")
                                        print(f"[SURICATA ALERT #{self.alert_count}]")
                                        print(f"    Time: {event.get('timestamp', 'N/A')}")
                                        print(f"    Signature: {event['alert'].get('signature', 'N/A')}")
                                        print(f"    Category: {event['alert'].get('category', 'N/A')}")
                                        print(f"    Severity: {event['alert'].get('severity', 'N/A')}")
                                        print(f"    Source: {event.get('src_ip', 'N/A')}:{event.get('src_port', 'N/A')}")
                                        print(f"    Destination: {event.get('dest_ip', 'N/A')}:{event.get('dest_port', 'N/A')}")
                                        print(f"    Protocol: {event.get('proto', 'N/A')}")
                                        print(f"{'⚠️'*60}\n")
                                except json.JSONDecodeError:
                                    continue
                            last_position = f.tell()
                except Exception as e:
                    pass
                time.sleep(1)
        
        monitor_thread = threading.Thread(target=monitor_alerts, daemon=True)
        monitor_thread.start()
        print("[+] Alert monitor started")

    def write_packet(self, data, addr):
        """Write packet to PCAP file"""
        if not self.pcap_handle:
            return
        
        # PCAP packet header
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

    def signal_handler(self, sig, frame):
        print(f"\n{'═'*60}")
        print("[⏹] Shutting down Suricata receiver...")
        self.running = False
        
        elapsed = time.time() - self.start_time
        
        if self.pcap_handle:
            self.pcap_handle.close()
        
        if self.suricata_process:
            self.suricata_process.terminate()
        
        print(f"[+] Statistics:")
        print(f"    Runtime: {elapsed:.1f} seconds")
        print(f"    Packets received: {self.packet_count}")
        print(f"    Alerts generated: {self.alert_count}")
        print(f"    Rate: {self.packet_count/elapsed:.1f} packets/sec")
        sys.exit(0)

    def start(self):
        """Start the receiver"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind(('0.0.0.0', SURICATA_PORT))
            print(f"[+] Listening on 0.0.0.0:{SURICATA_PORT}")
        except Exception as e:
            print(f"[-] Bind failed: {e}")
            sys.exit(1)
        
        print("[+] Waiting for packets...\n")
        sock.settimeout(1.0)
        
        while self.running:
            try:
                data, addr = sock.recvfrom(65535)
                self.packet_count += 1
                
                if time.time() - self.last_rotation > 3600:
                    self.create_pcap()
                    self.last_rotation = time.time()
                    if self.suricata_process:
                        self.suricata_process.terminate()
                    self.start_suricata_analysis()
                
                self.write_packet(data, addr)
                
                if self.packet_count % 100 == 0:
                    elapsed = time.time() - self.start_time
                    print(f"[📊] Suricata: {self.packet_count} packets, "
                          f"{self.alert_count} alerts ({self.packet_count/elapsed:.1f}/sec)")
                
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[-] Error: {e}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] Please run as root (sudo)")
        sys.exit(1)
    
    receiver = IntegratedSuricataReceiver()
    receiver.start()
