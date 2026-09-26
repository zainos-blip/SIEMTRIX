                      
"""
Complete live dashboard debug script.
Tests: IT login → DMZ token retrieval → DMZ session polling → command submission → session update.
"""
import requests, json, time, os, sys

                                                       
try:
    from config import settings
    DMZ_BASE = settings.dmz_base_url
except ImportError:
    print("Could not import config; trying local .env")
    from dotenv import load_dotenv
    load_dotenv()
    DMZ_BASE = os.getenv("DMZ_BASE_URL", "https://entrap-underfed-collapse.ngrok-free.dev")

IT_BASE = "http://localhost:8000"                                             

USER = "Admin1"
PASS = "password1"                                      

                                        
print("1️⃣  IT login...")
resp = requests.post(f"{IT_BASE}/api/v1/login", json={"username": USER, "password": PASS}, timeout=10)
if resp.status_code != 200:
    print(f"   ❌ Login failed ({resp.status_code}): {resp.text}")
    sys.exit(1)
data = resp.json()
jwt_token = data.get("access_token")
dmz_token = data.get("dmz_session_token")
print(f"   ✅ Got JWT: {jwt_token[:30]}...")
print(f"   ✅ Got DMZ token: {dmz_token}")

                                                                             
print("\n2️⃣  Polling DMZ session (should be empty)...")
if not dmz_token:
    print("   ❌ DMZ token is None – DMZ login failed (check params vs json)")
else:
    resp = requests.get(f"{DMZ_BASE}/api/session/commands",
                        headers={"x-session-token": dmz_token}, timeout=10)
    if resp.status_code == 200:
        cmds = resp.json()
        print(f"   ✅ DMZ session returned {len(cmds)} commands (expected 0)")
    else:
        print(f"   ❌ DMZ session failed ({resp.status_code}): {resp.text[:200]}")

                                                                            
print("\n3️⃣  Submitting a test command...")
cmd_payload = {
    "command_type": "r",
    "device_id": "plc-001",
    "register": 40001,
    "priority": "normal",
    "issued_by": USER,
    "description": "dashboard debug test"
}
headers = {
    "Authorization": f"Bearer {jwt_token}",
    "X-DMZ-Session-Token": dmz_token
}
resp = requests.post(f"{IT_BASE}/api/submit_command", json=cmd_payload,
                     headers=headers, timeout=10)
if resp.status_code == 200:
    cid = resp.json().get("command_id")
    print(f"   ✅ Command submitted (ID: {cid})")
else:
    print(f"   ❌ Command failed ({resp.status_code}): {resp.text[:200]}")
    sys.exit(1)

                                                               
print("\n4️⃣  Waiting 2s for DMZ processing...")
time.sleep(2)

print("   Polling DMZ session again...")
resp = requests.get(f"{DMZ_BASE}/api/session/commands",
                    headers={"x-session-token": dmz_token}, timeout=10)
if resp.status_code != 200:
    print(f"   ❌ DMZ session failed ({resp.status_code}): {resp.text[:200]}")
else:
    cmds = resp.json()
    print(f"   ✅ Session now has {len(cmds)} command(s)")
    for cmd in cmds:
        print(f"   - {cmd['command_id']} | status={cmd['status']} | dmz_decision={cmd.get('dmz_decision')} | ml_score={cmd.get('ml_score')}")
                                     
    if any(c.get('command_id') == cid for c in cmds):
        print("   🎉 Your command is in the live dashboard data!")
    else:
        print(f"   ⚠️  Command ID {cid} not found in session – possible DMZ session token mismatch")

print("\n✅ Debug script finished.")