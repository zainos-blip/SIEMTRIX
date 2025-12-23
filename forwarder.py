#!/usr/bin/env python3
"""
COMPLETE OT Security Forwarder
Captures BOTH network (eth0) AND loopback (lo) traffic
"""
from scapy.all import *
import socket
import time
import threading

KALI_IP = "192.168.18.25"
PORT = 5555

# Ports
RABBITMQ_PORT = 5672
OT_PULLER_PORT = 8090
SCADABR_PORT = 9090
PLC_PORT = 5503

print(f"╔{'═'*60}╗")
print(f"║{'COMPLETE OT SECURITY FORWARDER':^60}║")
print(f"╠{'═'*60}╣")
print(f"║ Forwarding to: {KALI_IP}:{PORT:<31}║")
print(f"╠{'═'*60}╣")
print(f"║ CAPTURING FROM BOTH INTERFACES:                    ║")
print(f"║ • eth0: SCADA→PLC (5503) traffic                  ║")
print(f"║ • lo: RabbitMQ (5672) ↔ OT Puller (8090) traffic  ║")
print(f"╚{'═'*60}╝")
print(f"[+] Press Ctrl+C to stop\n")

# Create UDP socket for sending to Kali
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
packet_count = {"eth0": 0, "lo": 0, "total": 0}

def process_packet(pkt, interface):
    # Define Suricata and Zeek ports
    SURICATA_PORT = 5555
    ZEEK_PORT     = 5556

    # Forward packet to both ports
    try:
        pkt_bytes = bytes(pkt)
        sock.sendto(pkt_bytes, (KALI_IP, SURICATA_PORT))  # For Suricata
        sock.sendto(pkt_bytes, (KALI_IP, ZEEK_PORT))      # For Zeek
    except Exception as e:
        print(f"[-] Send error: {e}")

    
    packet_count["total"] += 1
    packet_count[interface] += 1
    
    if TCP in pkt:
        # Get IP info (IPv4 or IPv6)
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            ip_ver = "IPv4"
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
            ip_ver = "IPv6"
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
            # Response traffic
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
        
        # Get TCP flags
        flags = pkt[TCP].flags
        flag_str = ""
        if flags & 0x02: flag_str += "S"  # SYN
        if flags & 0x10: flag_str += "A"  # ACK
        if flags & 0x01: flag_str += "F"  # FIN
        if flags & 0x08: flag_str += "P"  # PSH (data)
        
        # Show interesting packets
        if service != "Unknown":
            interface_symbol = "🌐" if interface == "eth0" else "🔁"
            print(f"[{interface_symbol} {service:9}] {src_ip}:{src_port} {direction} [{flag_str}]")
        
        # Show progress every 50 packets
        if packet_count["total"] % 50 == 0:
            print(f"[📊] Progress: {packet_count['total']} total packets "
                  f"(eth0: {packet_count['eth0']}, lo: {packet_count['lo']})")
    
  
    

def capture_interface(interface, filter_str):
    """Capture packets from a specific interface"""
    try:
        print(f"[+] Starting capture on {interface} with filter: {filter_str}")
        sniff(iface=interface, 
              prn=lambda pkt: process_packet(pkt, interface), 
              store=False,
              filter=filter_str)
    except Exception as e:
        print(f"[-] Error on {interface}: {e}")

def main():
    # Create filters for each interface
    eth0_filter = f"""
    (tcp port {SCADABR_PORT} or tcp port {PLC_PORT}) or
    (ip6 and (tcp port {SCADABR_PORT} or tcp port {PLC_PORT}))
    """
    
    lo_filter = f"""
    (tcp port {RABBITMQ_PORT} or tcp port {OT_PULLER_PORT}) or
    (ip6 and (tcp port {RABBITMQ_PORT} or tcp port {OT_PULLER_PORT}))
    """
    
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
    
    print("[+] Starting capture threads...")
    eth0_thread.start()
    lo_thread.start()
    
    print("[+] Both interfaces monitoring active")
    print("[+] Waiting for traffic...\n")
    
    try:
        # Keep main thread alive
        while True:
            time.sleep(1)
            # Check if threads are still alive
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
        print(f"\n{'═'*60}")
        print(f"[✅] Capture stopped by user")
        print(f"{'═'*60}")
        print(f"[📊] FINAL STATISTICS:")
        print(f"    Total packets: {packet_count['total']}")
        print(f"    eth0 packets (SCADA→PLC): {packet_count['eth0']}")
        print(f"    lo packets (RabbitMQ↔OT Puller): {packet_count['lo']}")
        print(f"{'═'*60}")
    
    finally:
        sock.close()

if __name__ == "__main__":
    main()