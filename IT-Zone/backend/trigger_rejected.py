import requests
import time

BASE_URL = "http://localhost:8000/api/submit_command"

attacks = [
                    
    {
        "command_type": "w",
        "device_id": "PLC-001",
        "register": 40001,
        "value": -500,
        "priority": "critical",
        "description": "negative val test",
        "issued_by": "Admin1",
        "allow_malformed": True
    },
                             
    {
        "command_type": "w",
        "device_id": "PLC-001",
        "register": 40002,
        "value": 2000000,
        "priority": "normal",
        "description": "overflow test",
        "issued_by": "Admin1",
        "allow_malformed": True
    },
                                  
    {
        "command_type": "w",
        "device_id": "PLC-001",
        "register": 40001,
        "value": 12345,
        "priority": "normal",
        "description": "rbac test",
        "issued_by": "User1",
        "allow_malformed": True
    },
                      
    {
        "command_type": "r",
        "device_id": "PLC-001",
        "register": 49999,
        "priority": "normal",
        "description": "invalid reg test",
        "issued_by": "Admin1",
        "allow_malformed": True
    },
]

print("Sending DMZ rejection triggers...\n")
for i, cmd in enumerate(attacks, 1):
    resp = requests.post(BASE_URL, json=cmd)
    if resp.status_code == 200:
        data = resp.json()
        if data.get("status") == "blocked":
            print(f"✅ Attack {i} BLOCKED – reason: {data.get('reason', 'DMZ rejection')}")
        else:
            print(f"⚠️  Attack {i} sent (unexpected) – status: {data.get('status')}")
    else:
        print(f"❌ Attack {i} HTTP {resp.status_code}: {resp.text[:100]}")
    time.sleep(0.5)

print("\nDone. Now check your Splunk dashboard for rejected commands.")