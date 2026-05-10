#!/usr/bin/env python3
"""
Integrated Zeek OT Receiver - COMPLETE WORKING VERSION with Custom OpenModsim Logs
Captures packets, saves to PCAP, and processes them with Zeek
Generates ALL standard Zeek logs PLUS custom static_openmodsim.log (non‑rotating)
UPDATED: Custom script logs ports 1502, 8090, 5672, 502.
"""
import socket
import os
import sys
import time
import signal
import struct
import subprocess
import threading
from datetime import datetime

# Configuration
ZEEK_PORT = 5556
PCAP_DIR = "/opt/zeek/ot_traffic"
LOG_DIR = "/opt/zeek/logs/current"

os.makedirs(PCAP_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

class IntegratedZeekReceiver:
    def __init__(self):
        self.running = True
        self.packet_count = 0
        self.pcap_file = None
        self.pcap_handle = None
        self.last_rotation = time.time()
        self.start_time = time.time()
        self.processed_pcaps = set()
        
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Create custom Zeek script for OpenModsim logs (now includes multiple ports)
        self.create_custom_zeek_script()
        
        self.create_pcap()
        self.start_pcap_processor()
        self.start_log_monitor()
        
        self.print_banner()

    def print_banner(self):
        print(f"╔{'═'*60}╗")
        print(f"║{'ZEEK RECEIVER - FULL ANALYSIS + CUSTOM LOGS':^60}║")
        print(f"╠{'═'*60}╣")
        print(f"║ Listening on port: {ZEEK_PORT:<42}║")
        print(f"║ PCAP directory: {PCAP_DIR:<42}║")
        print(f"║ Log directory: {LOG_DIR:<42}║")
        print(f"║ Custom log: static_openmodsim.log{' ' * 30}║")
        print(f"║ Logging ports: 1502, 8090, 5672, 502{' ' * 23}║")
        print(f"╚{'═'*60}╝")

    def create_custom_zeek_script(self):
        """Create custom Zeek script for OT PLC and API logs (ports 1502, 8090, 5672, 502) – STATIC filename"""
        script_path = "/opt/zeek/share/zeek/site/openmodsim.zeek"
        os.makedirs("/opt/zeek/share/zeek/site", exist_ok=True)
        
        with open(script_path, 'w') as f:
            f.write("""# Custom OT logging - Partner's desired format
# Logs connections on ports: 1502 (PLC/Modbus), 8090 (OT Puller API), 5672 (RabbitMQ), 502 (Modbus)
module OpenModsim;

export {
    redef enum Log::ID += { LOG };
    
    type Info: record {
        ts: time &log;
        src_ip: addr &log;
        src_port: port &log;
        dst_ip: addr &log;
        dst_port: port &log;
        orig_bytes: count &log &optional;
        resp_bytes: count &log &optional;
        placeholder1: string &log &optional;
        placeholder2: string &log &optional;
        placeholder3: string &log &optional;
    };
}

event zeek_init() {
    # Use a static, non‑rotated filename
    Log::create_stream(OpenModsim::LOG, [$columns=Info, $path="/opt/zeek/logs/current/static_openmodsim"]);
}

event connection_state_remove(c: connection) {
    # Log OT traffic on relevant ports: 1502 (PLC), 8090 (API), 5672 (RabbitMQ), 502 (Modbus)
    local ot_ports = set(1502/tcp, 8090/tcp, 5672/tcp, 502/tcp);
    if (c$id$resp_p in ot_ports || c$id$orig_p in ot_ports) {
        local rec: OpenModsim::Info = [
            $ts=network_time(),
            $src_ip=c$id$orig_h,
            $src_port=c$id$orig_p,
            $dst_ip=c$id$resp_h,
            $dst_port=c$id$resp_p,
            $orig_bytes = (c$conn?$orig_bytes ? c$conn$orig_bytes : 0),
            $resp_bytes = (c$conn?$resp_bytes ? c$conn$resp_bytes : 0),
            $placeholder1="-",
            $placeholder2="-",
            $placeholder3="-"
        ];
        Log::write(OpenModsim::LOG, rec);
    }
}
""")
        print(f"[+] Custom Zeek script created: {script_path} (logging ports 1502, 8090, 5672, 502)")

    def create_pcap(self):
        """Create a new PCAP file with proper header"""
        if self.pcap_handle:
            self.pcap_handle.close()
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.pcap_file = os.path.join(PCAP_DIR, f"zeek_input_{timestamp}.pcap")
        
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
        
        # Create symlink for current PCAP
        current_link = os.path.join(PCAP_DIR, "current.pcap")
        if os.path.exists(current_link):
            os.unlink(current_link)
        try:
            os.symlink(self.pcap_file, current_link)
        except:
            pass
        
        print(f"[+] New PCAP: {self.pcap_file}")

    def process_pcap_with_zeek(self, pcap_file):
        """Process a completed PCAP file with Zeek - FULL analysis + custom logs"""
        if not os.path.exists(pcap_file):
            return
        
        if pcap_file in self.processed_pcaps:
            return
            
        filename = os.path.basename(pcap_file)
        print(f"\n[⚙] Processing {filename} with Zeek...")
        
        # Change to log directory before running Zeek
        original_dir = os.getcwd()
        os.chdir(LOG_DIR)
        
        try:
            # Run Zeek on the PCAP file with BOTH:
            # - "local" for full Zeek analysis (generates all standard logs)
            # - custom script for partner's desired static_openmodsim.log format
            cmd = ["/opt/zeek/bin/zeek", "-C", "-r", pcap_file, 
                   "local",                                # Full Zeek analysis
                   "/opt/zeek/share/zeek/site/openmodsim.zeek"]  # Custom format
            
            # Run Zeek
            process = subprocess.run(cmd, 
                                   stdout=subprocess.PIPE, 
                                   stderr=subprocess.PIPE,
                                   text=True,
                                   timeout=30)
            
            # Show any errors (but not warnings)
            if process.stderr:
                for line in process.stderr.split('\n'):
                    if line.strip() and "warning" not in line.lower() and "fatal" not in line.lower():
                        print(f"[ZEEK] {line}")
            
            # Wait a moment for logs to be written
            time.sleep(2)
            
            # List the logs that were created/updated
            current_time = time.time()
            log_files = []
            for f in os.listdir(LOG_DIR):
                if f.endswith('.log'):
                    f_path = os.path.join(LOG_DIR, f)
                    if current_time - os.path.getmtime(f_path) < 60:
                        log_files.append(f)
            
            if log_files:
                print(f"[✓] Generated logs: {', '.join(log_files[:5])}")
                if len(log_files) > 5:
                    print(f"    ... and {len(log_files)-5} more")
                    
            self.processed_pcaps.add(pcap_file)
            
        except subprocess.TimeoutExpired:
            print(f"[-] Zeek processing timeout for {filename}")
        except Exception as e:
            print(f"[-] Error processing {filename}: {e}")
        finally:
            os.chdir(original_dir)

    def start_pcap_processor(self):
        """Background thread to process completed PCAPs"""
        def processor():
            print("[+] PCAP processor started")
            
            while self.running:
                try:
                    # Get all PCAP files
                    pcaps = []
                    for f in os.listdir(PCAP_DIR):
                        if f.endswith('.pcap') and f != os.path.basename(self.pcap_file):
                            pcap_path = os.path.join(PCAP_DIR, f)
                            pcaps.append((os.path.getmtime(pcap_path), pcap_path))
                    
                    # Sort by modification time (oldest first)
                    pcaps.sort()
                    
                    # Process each unprocessed PCAP
                    for _, pcap_path in pcaps:
                        if pcap_path not in self.processed_pcaps:
                            # Check if file is stable (not being written to)
                            size1 = os.path.getsize(pcap_path)
                            time.sleep(1)
                            size2 = os.path.getsize(pcap_path)
                            
                            if size1 == size2 and size1 > 0:
                                self.process_pcap_with_zeek(pcap_path)
                    
                except Exception as e:
                    print(f"[-] Processor error: {e}")
                
                time.sleep(10)
        
        processor_thread = threading.Thread(target=processor, daemon=True)
        processor_thread.start()

    def start_log_monitor(self):
        """Monitor Zeek logs and display interesting connections"""
        def monitor():
            last_positions = {}
            print("[+] Log monitor started")
            
            while self.running:
                try:
                    # Monitor conn.log for OT traffic
                    conn_log = os.path.join(LOG_DIR, "conn.log")
                    if os.path.exists(conn_log):
                        with open(conn_log, 'r') as f:
                            f.seek(last_positions.get('conn', 0))
                            for line in f:
                                if line.strip() and not line.startswith('#'):
                                    if any(port in line for port in ['502', '1502', '20000', '102']):
                                        parts = line.split()
                                        if len(parts) >= 9:
                                            print(f"\n[ZEEK OT] {parts[2]}:{parts[3]} -> {parts[4]}:{parts[5]}")
                            last_positions['conn'] = f.tell()
                    
                    # Monitor notice.log
                    notice_log = os.path.join(LOG_DIR, "notice.log")
                    if os.path.exists(notice_log):
                        with open(notice_log, 'r') as f:
                            f.seek(last_positions.get('notice', 0))
                            for line in f:
                                if line.strip() and not line.startswith('#'):
                                    print(f"\n[ZEEK NOTICE] {line.strip()}")
                            last_positions['notice'] = f.tell()
                    
                except Exception:
                    pass
                time.sleep(3)
        
        monitor_thread = threading.Thread(target=monitor, daemon=True)
        monitor_thread.start()

    def write_packet(self, data):
        """Write packet to PCAP file"""
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

    def signal_handler(self, sig, frame):
        print(f"\n{'═'*60}")
        print("[⏹] Shutting down Zeek receiver...")
        self.running = False
        elapsed = time.time() - self.start_time
        
        if self.pcap_handle:
            self.pcap_handle.close()
        
        if self.pcap_file and os.path.exists(self.pcap_file) and self.pcap_file not in self.processed_pcaps:
            print("[+] Processing final PCAP...")
            self.process_pcap_with_zeek(self.pcap_file)
        
        print(f"\n[+] Statistics:")
        print(f"    Runtime: {elapsed:.1f} seconds")
        print(f"    Packets received: {self.packet_count}")
        if elapsed > 0:
            print(f"    Rate: {self.packet_count/elapsed:.1f} packets/sec")
        print(f"    PCAPs processed: {len(self.processed_pcaps)}")
        print(f"{'═'*60}")
        sys.exit(0)

    def start(self):
        """Start the receiver"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind(('0.0.0.0', ZEEK_PORT))
            print(f"[+] Listening on 0.0.0.0:{ZEEK_PORT}")
        except Exception as e:
            print(f"[-] Bind failed: {e}")
            sys.exit(1)
        
        print("[+] Waiting for packets...\n")
        sock.settimeout(1.0)
        
        while self.running:
            try:
                data, addr = sock.recvfrom(65535)
                self.packet_count += 1
                
                self.write_packet(data)
                
                if time.time() - self.last_rotation > 3600:
                    self.create_pcap()
                    self.last_rotation = time.time()
                
                if self.packet_count % 100 == 0:
                    elapsed = time.time() - self.start_time
                    rate = self.packet_count / elapsed if elapsed > 0 else 0
                    print(f"[📊] Zeek: {self.packet_count} packets ({rate:.1f}/sec)")
                
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[-] Error: {e}")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[-] Please run as root (sudo)")
        sys.exit(1)
    
    receiver = IntegratedZeekReceiver()
    receiver.start()
