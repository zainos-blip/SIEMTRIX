import requests
import time
import random
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

                                     
BASE_URL = "http://localhost:8000/api/submit_command"                   
DMZ_URL  = "https://entrap-underfed-collapse.ngrok-free.dev/process_enqueue"              
SAFE_TS = "2026-04-29T10:00:00Z"                                                 

def run_attacks(jwt_token=None, dmz_token=None):
    from config import settings
    
    IT_BASE = "http://localhost:8000"
    DMZ_URL = f"{settings.dmz_base_url}/process_enqueue"
    
    results = {"total": 0, "blocked": 0, "passed": 0, "ml_flagged": 0, "details": []}
    
    headers = {}
    if jwt_token:
        headers["Authorization"] = f"Bearer {jwt_token}"
    if dmz_token:
        headers["X-DMZ-Session-Token"] = dmz_token

    def send_command(cmd, desc, malformed=False):
        results["total"] += 1
        payload = cmd.copy()
        if malformed:
            payload["allow_malformed"] = True
        if "timestamp" not in payload:
            payload["timestamp"] = SAFE_TS

        print(f"\n>>> {desc}")
        print(f"    Payload: {payload}")

        try:
            resp = requests.post(f"{IT_BASE}/api/submit_command", json=payload, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("status", "unknown")
                if status == "blocked" or data.get("decision") == "rejected":
                    reason = data.get("reason", "DMZ rejection")
                    print(f"    🚫 BLOCKED (reason: {reason})")
                    results["blocked"] += 1
                    if "ml" in reason.lower() or data.get("ml_flagged"):
                        results["ml_flagged"] += 1
                else:
                    print(f"    ✅ Sent (command_id: {data.get('command_id')})")
                    results["passed"] += 1
                results["details"].append(data)
            elif resp.status_code == 422:
                print(f"    ⚠️ Validation error (422) – caught by web‑app filter")
                results["blocked"] += 1
                results["details"].append({"error": "422 Validation Error", "text": resp.text})
            else:
                print(f"    ❌ HTTP {resp.status_code}: {resp.text[:150]}")
                results["blocked"] += 1
                results["details"].append({"error": f"HTTP {resp.status_code}", "text": resp.text})
        except Exception as e:
            print(f"    ❌ Request failed: {e}")
            results["blocked"] += 1
            results["details"].append({"error": str(e)})

    def send_dmz(payload, desc):
        results["total"] += 1
        print(f"\n>>> {desc}")
        print(f"    Payload: {payload}")
        
        dmz_headers = {}
        if dmz_token:
            dmz_headers["x-session-token"] = dmz_token
            
        try:
            resp = requests.post(DMZ_URL, json=payload, headers=dmz_headers, timeout=10)
            if resp.status_code == 200:
                print("    ✅ DMZ accepted the command")
                results["passed"] += 1
            else:
                print(f"    🚫 DMZ BLOCKED (status {resp.status_code}): {resp.text.strip()}")
                results["blocked"] += 1
        except Exception as e:
            print(f"    ❌ DMZ request failed: {e}")
            results["blocked"] += 1

                                                                           
                                                   
                                                                           
    print("=" * 60)
    print("SENDING NORMAL COMMANDS (should be ALLOWED or SUSPICIOUS for high values)")
    for i in range(5):
        cmd = {
            "command_type": "w",
            "device_id": "PLC-001",
            "register": random.choice([40001, 40002, 40003, 40004, 40005]),
            "value": random.choice([1, 100, 5000, 32768, 65535]),
            "priority": "normal",
            "description": "normal operation",
            "issued_by": "Admin1",
            "timestamp": SAFE_TS
        }
        send_command(cmd, f"Normal write {cmd['value']}")
        time.sleep(0.3)

                                                                           
                               
                                                                           
    print("\n" + "=" * 60)
    print("ML ATTACK VECTORS (all should be BLOCKED)")

                            
    send_command(
        {"command_type":"w","device_id":"PLC-001","register":40001,"value":12345,
         "priority":"normal","issued_by":"User1","description":"rbac test"},
        "1. RBAC (User1 write)", malformed=True)

                                  
    send_command(
        {"command_type":"r","device_id":"PLC-001","register":49999,
         "priority":"normal","issued_by":"Admin1","description":"invalid reg"},
        "2. Invalid register (49999)", malformed=True)

                             
    send_command(
        {"command_type":"w","device_id":"PLC-001","register":40002,"value":2000000,
         "priority":"normal","issued_by":"Admin1","description":"overflow"},
        "3. Value overflow (2M)", malformed=True)

                        
    send_command(
        {"command_type":"w","device_id":"PLC-001","register":40001,"value":-500,
         "priority":"critical","issued_by":"Admin1","description":"neg val"},
        "4. Negative value", malformed=True)

                      
    send_command(
        {"command_type":"r","device_id":"PLC-001","register":40001,"value":None,
         "priority":"normal","issued_by":"Attacker","description":"unk user"},
        "5. Unknown user", malformed=True)

                              
    send_command(
        {"command_type":"delete","device_id":"PLC-001","register":40001,"value":None,
         "priority":"normal","issued_by":"Admin1","description":"unk cmd"},
        "6. Unknown command type", malformed=True)

                          
    send_command(
        {"command_type":"r","device_id":"PLC-001","register":40001,"value":None,
         "priority":"high","issued_by":"Admin1","description":"unk pri"},
        "7. Unknown priority", malformed=True)

                                                
    send_command(
        {"command_type":"r","device_id":"PLC-001","register":40001,"value":None,
         "priority":"normal","function_code":6,"issued_by":"Admin1","description":"func mismatch"},
        "8. Function code mismatch (read+func6)", malformed=True)

                                                   
    send_command(
        {"command_type":"w","device_id":"PLC-001","register":40001,"value":-9999,
         "priority":"normal","issued_by":"Admin1","description":"null write"},
        "9. Null write value (sentinel)", malformed=True)

                                                                   
    send_command(
        {"command_type":"r","device_id":"PLC-001","register":"HR_ABC","value":None,
         "priority":"normal","issued_by":"Admin1","description":"malf reg"},
        "10. Malformed register (422 expected)", malformed=True)

                                    
    send_command(
        {"command_type":"r","device_id":"PLC-001","register":40001,"value":None,
         "priority":"normal","function_code":1,"issued_by":"Admin1","description":"unusual func"},
        "11. Unusual function code 1", malformed=True)

                                          
    send_command(
        {"command_type":"r","device_id":"PLC-001","register":40001,"value":9999,
         "priority":"normal","issued_by":"Admin1","description":"read+val"},
        "12. Read with non-zero value", malformed=True)

                                       
    send_command(
        {"command_type":"r","device_id":"PLC-001","register":40001,"value":None,
         "priority":"normal","issued_by":"Admin1","description":"A"*350},
        "13. Long description (350 chars)", malformed=True)

                             
    send_command(
        {"command_type":"r","device_id":"PLC-001","register":40001,"value":None,
         "priority":"normal","issued_by":"Admin1","description":"shutdown system"},
        "14. Suspicious keyword", malformed=True)

                                                  
    send_command(
        {"command_type":"r","device_id":"PLC-001","register":40001,"value":None,
         "priority":"normal","issued_by":"Admin1","description":""},
        "15. Empty description", malformed=True)

                                   
    send_command(
        {"command_type":"r","device_id":"PLC-999","register":40001,"value":None,
         "priority":"normal","issued_by":"Admin1","description":"bad dev"},
        "16. Invalid device PLC-999", malformed=True)

                                     
    send_command(
        {"command_type":"r","device_id":"PLC-001","register":40001,"value":None,
         "priority":"normal","issued_by":"Admin1","description":"off-hours",
         "timestamp":"2026-04-26T03:00:00Z"},
        "17. Off-hours", malformed=True)

                                         
    send_command(
        {"command_type":"r","device_id":"PLC-001","register":40001,"value":None,
         "priority":"normal","issued_by":"","description":"missing user"},
        "18. Missing user", malformed=True)

                        
    send_command(
        {"command_type":"r","device_id":"PLC-001","register":0,"value":None,
         "priority":"normal","issued_by":"Admin1","description":"reg zero"},
        "19. Register zero", malformed=True)

                                    
    send_command(
        {"command_type":"r","device_id":"PLC-001","register":99999,"value":None,
         "priority":"normal","issued_by":"Admin1","description":"reg overflow"},
        "20. Register overflow", malformed=True)

                                 
    send_command(
        {"command_type":"r","device_id":"PLC-001","register":40001,"value":None,
         "priority":"normal","issued_by":"Admin1","description":"   \t  "},
        "21. Whitespace description", malformed=True)

                                                       
    send_command(
        {"command_type":"w","device_id":"PLC-001","register":49999,"value":9999999,
         "priority":"critical","issued_by":"User1","description":"mixed attack"},
        "22. Mixed (User1 write + invalid reg + overflow)", malformed=True)

                                                                           
                              
                                                                           
    send_command(
        {"command_type":"w","device_id":"PLC-001","register":40001,"value":65536,
         "priority":"normal","issued_by":"Admin1","description":"boundary"},
        "Boundary 65536 (should be BLOCKED by static rule)", malformed=True)

                                                                           
                                   
                                                                           
    print("\n" + "=" * 60)
    print("STATIC RULE DEMONSTRATIONS")
    print("⚠️  Before running, ensure the DMZ rate limit is lowered for visible burst effect:")
    print("    export RATE_LIMIT_MAX=3")
    print("    export RATE_LIMIT_WINDOW=5.0")
    print("    Then restart DMZ API.\n")

                                                                              
    replay_id = f"CMD-{uuid.uuid4().hex[:12].upper()}"                          
    replay_payload = {
        "command_type": "r",
        "device_id": "PLC-001",
        "register_number": "HR_40001",
        "value": None,
        "priority": "normal",
        "description": "replay test",
        "issued_by": "Admin1",
        "function_code": 3,
        "command_id": replay_id,
        "timestamp": SAFE_TS
    }
    send_dmz(replay_payload, f"Replay – first send (ID: {replay_id}, should be ALLOWED)")
    time.sleep(0.8)
    send_dmz(replay_payload, f"Replay – duplicate (same ID, should be BLOCKED)")

                                                            
    print("\n>>> Concurrent burst test (8 simultaneous writes via threads)")
    burst_ids = [f"CMD-{uuid.uuid4().hex[:12].upper()}" for _ in range(8)]
    burst_template = {
        "command_type": "w",
        "device_id": "PLC-001",
        "register_number": "HR_40001",
        "value": 1234,
        "priority": "normal",
        "description": "burst test",
        "issued_by": "Admin1",
        "function_code": 6,
        "timestamp": SAFE_TS
    }

    def fire_burst(i):
        payload = burst_template.copy()
        payload["command_id"] = burst_ids[i-1]
        dmz_headers = {}
        if dmz_token:
            dmz_headers["x-session-token"] = dmz_token
        try:
            resp = requests.post(DMZ_URL, json=payload, headers=dmz_headers, timeout=10)
            return i, resp.status_code, resp.text.strip()
        except Exception as e:
            return i, 500, str(e)

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(fire_burst, i+1) for i in range(8)]
        for future in as_completed(futures):
            results["total"] += 1
            i, status, text = future.result()
            if status == 200:
                print(f"   Burst {i}: ALLOWED")
                results["passed"] += 1
            else:
                print(f"   Burst {i}: 🚫 BLOCKED ({text[:120]})")
                results["blocked"] += 1

    print("\n" + "=" * 60)
    print("ATTACK SIMULATION COMPLETE.")
    print("👉 Check Splunk dashboards for real‑time decisions.")
    
    return results

if __name__ == "__main__":
    run_attacks()