#!/usr/bin/env python3
"""
COMPLETE OT Security Forwarder - UPDATED for Bridged Network
Captures BOTH network (eth0) AND loopback (lo) traffic
"""
from scapy.all import *
import socket
import time
import threading

# ===== UPDATED CONFIGURATION =====
# Your Kali VM new IP (bridged mode)
KALI_IP = "192.168.18.38"  # <-- CHANGE THIS to your new Kali IP

# If direct to Kali doesn't work, use Windows as relay:
WINDOWS_HOST_IP = "192.168.18.106"  # Your Windows host IP
USE_WINDOWS_RELAY = False  # Set to True if direct connection fails

# Determine target IP
TARGET_IP = WINDOWS_HOST_IP if USE_WINDOWS_RELAY else KALI_IP
# =================================

# Ports
RABBITMQ_PORT = 5672
OT_PULLER_PORT = 8090
SCADABR_PORT = 9090
PLC_PORT = 1502 

# Suricata and Zeek ports on Kali
SURICATA_PORT = 5555
ZEEK_PORT = 5556

print(f"╔{'═'*60}╗")
print(f"║{'COMPLETE OT SECURITY FORWARDER':^60}║")
print(f"╠{'═'*60}╣")
print(f"║ Forwarding to: {TARGET_IP}:{SURICATA_PORT}/{ZEEK_PORT}        ║")
print(f"║ Kali IP: {KALI_IP} (bridged mode)                 ║")
print(f"║ Windows Relay: {'ENABLED' if USE_WINDOWS_RELAY else 'DISABLED'}                      ║")
print(f"╠{'═'*60}╣")
print(f"║ CAPTURING FROM BOTH INTERFACES:                    ║")
print(f"║ • eth0: SCADA→PLC ({PLC_PORT}) traffic            ║")
print(f"║ • lo: RabbitMQ ({RABBITMQ_PORT}) ↔ OT Puller ({OT_PULLER_PORT})  ║")
print(f"╚{'═'*60}╝")
print(f"[+] Press Ctrl+C to stop\n")

# Create UDP socket for sending
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
packet_count = {"eth0": 0, "lo": 0, "total": 0}
start_time = time.time()

def process_packet(pkt, interface):
    try:
        pkt_bytes = bytes(pkt)
        
        # Forward packet to both Suricata and Zeek ports
        sock.sendto(pkt_bytes, (TARGET_IP, SURICATA_PORT))
        sock.sendto(pkt_bytes, (TARGET_IP, ZEEK_PORT))
        
    except Exception as e:
        print(f"[-] Send error: {e}")
        return

    packet_count["total"] += 1
    packet_count[interface] += 1

    # Show packet details for OT traffic
    if TCP in pkt:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        else:
            return

        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport

        # Determine service and direction
        service = "Unknown"
        direction = ""

        if dst_port == RABBITMQ_PORT:
            service = "RabbitMQ"
            direction = "→ RabbitMQ"
        elif dst_port == OT_PULLER_PORT:
            service = "OT Puller"
            direction = "→ OT Puller"
        elif dst_port == SCADABR_PORT:
            service = "SCADA"
            direction = "→ SCADA"
        elif dst_port == PLC_PORT:
            service = "PLC"
            direction = "→ PLC"
        elif src_port in [RABBITMQ_PORT, OT_PULLER_PORT, SCADABR_PORT, PLC_PORT]:
            if src_port == RABBITMQ_PORT:
                service = "RabbitMQ"
                direction = "← RabbitMQ"
            elif src_port == OT_PULLER_PORT:
                service = "OT Puller"
                direction = "← OT Puller"
            elif src_port == SCADABR_PORT:
                service = "SCADA"
                direction = "← SCADA"
            elif src_port == PLC_PORT:
                service = "PLC"
                direction = "← PLC"

        # Show OT traffic immediately
        if service != "Unknown":
            interface_symbol = "🌐" if interface == "eth0" else "🔁"
            print(f"[{interface_symbol} {service:9}] {src_ip}:{src_port} {direction}")

    # Show progress every 50 packets
    if packet_count["total"] % 50 == 0:
        elapsed = time.time() - start_time
        rate = packet_count["total"] / elapsed if elapsed > 0 else 0
        print(f"[📊] Progress: {packet_count['total']} packets "
              f"(eth0: {packet_count['eth0']}, lo: {packet_count['lo']}) "
              f"[{rate:.1f} pkt/sec]")

def capture_interface(interface, filter_str):
    """Capture packets from a specific interface"""
    try:
        print(f"[+] Starting capture on {interface}")
        sniff(iface=interface,
              prn=lambda pkt: process_packet(pkt, interface),
              store=False,
              filter=filter_str)
    except Exception as e:
        print(f"[-] Error on {interface}: {e}")

def main():
    # First, test connectivity to target
    print("[+] Testing connectivity...")
    test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    test_sock.settimeout(2)
    try:
        test_sock.sendto(b"TEST", (TARGET_IP, SURICATA_PORT))
        print(f"[✓] Can reach {TARGET_IP}:{SURICATA_PORT}")
    except Exception as e:
        print(f"[✗] Cannot reach {TARGET_IP}:{SURICATA_PORT}")
        print(f"    Error: {e}")
        print(f"    If direct fails, set USE_WINDOWS_RELAY = True")
    test_sock.close()
    
    # Create filters
    eth0_filter = f"tcp port {SCADABR_PORT} or tcp port {PLC_PORT}"
    lo_filter = f"tcp port {RABBITMQ_PORT} or tcp port {OT_PULLER_PORT}"
    
    print(f"\n[+] Filters:")
    print(f"    eth0: {eth0_filter}")
    print(f"    lo:   {lo_filter}")
    
    # Start capture threads
    eth0_thread = threading.Thread(
        target=capture_interface,
        args=("eth0", eth0_filter),
        daemon=True
    )

    lo_thread = threading.Thread(
        target=capture_interface,
        args=("lo", lo_filter),
        daemon=True
    )

    print("\n[+] Starting capture threads...")
    eth0_thread.start()
    lo_thread.start()

    print("[+] Both interfaces monitoring active")
    print(f"[+] Forwarding to: {TARGET_IP}:{SURICATA_PORT} (Suricata) and {ZEEK_PORT} (Zeek)")
    print("[+] Waiting for OT traffic...\n")

    try:
        while True:
            time.sleep(1)
            if not eth0_thread.is_alive() or not lo_thread.is_alive():
                print("[!] One capture thread died. Restarting...")
                if not eth0_thread.is_alive():
                    eth0_thread = threading.Thread(
                        target=capture_interface,
                        args=("eth0", eth0_filter),
                        daemon=True
                    )
                    eth0_thread.start()
                if not lo_thread.is_alive():
                    lo_thread = threading.Thread(
                        target=capture_interface,
                        args=("lo", lo_filter),
                        daemon=True
                    )
                    lo_thread.start()

    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        print(f"\n{'═'*60}")
        print(f"[✅] Capture stopped by user")
        print(f"{'═'*60}")
        print(f"[📊] FINAL STATISTICS:")
        print(f"    Runtime: {elapsed:.1f} seconds")
        print(f"    Total packets: {packet_count['total']}")
        print(f"    eth0 packets (SCADA→PLC): {packet_count['eth0']}")
        print(f"    lo packets (RabbitMQ↔OT Puller): {packet_count['lo']}")
        print(f"    Average rate: {packet_count['total']/elapsed:.1f} pkt/sec")
        print(f"{'═'*60}")

    finally:
        sock.close()

if __name__ == "__main__":
    main()
