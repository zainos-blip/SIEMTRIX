import requests
import random
import time

               
BASE_URL = "http://localhost:8000"
LOGIN_URL = f"{BASE_URL}/api/login"
COMMAND_URL = f"{BASE_URL}/api/submit_command"

                        
USERS = {
    "Admin1": {"username": "Admin1", "password": "admin123"},
    "User1":  {"username": "User1",  "password": "user11"}
}

DEVICE = "plc-001"
REGISTERS = [40001, 40002, 40003, 40004, 40005]
TOTAL_COMMANDS = 3000

                           
                
                           
def login(username, password):
    """Authenticate and return a session with cookies."""
    session = requests.Session()
    resp = session.post(LOGIN_URL, json={"username": username, "password": password})
    if resp.status_code != 200:
        raise Exception(f"Login failed for {username}: {resp.status_code} - {resp.text}")
    print(f"✅ Logged in as {username} (role: {resp.json().get('role')})")
    return session

                               
sessions = {
    "Admin1": login(USERS["Admin1"]["username"], USERS["Admin1"]["password"]),
    "User1":  login(USERS["User1"]["username"], USERS["User1"]["password"])
}

                           
                  
                           
def random_description():
    return random.choice([
        "sensor polling", "temperature check", "pressure monitoring",
        "system heartbeat", "routine scan", "control update",
        "diagnostic cycle", "device sync"
    ])

def generate_value():
    cluster = random.random()
    if cluster < 0.6:
        return random.randint(500, 8000)
    elif cluster < 0.9:
        return random.randint(8000, 30000)
    else:
        return random.randint(30000, 45000)

                           
                       
                           
print("\n🔥 Warming up registers...")
for reg in REGISTERS:
    payload = {
        "command_type": "w",
        "device_id": DEVICE,
        "register": reg,
        "priority": "normal",
        "description": "initial system baseline",
        "issued_by": "Admin1",
        "value": generate_value()
    }
    resp = sessions["Admin1"].post(COMMAND_URL, json=payload)
    if resp.status_code == 200:
        print(f"   [INIT] Admin1 -> write | Reg {reg}")
    else:
        print(f"   ⚠️ Init failed: {resp.status_code}")
    time.sleep(0.1)

print("✅ Warm-up complete.\n")

                           
                         
                           
print("🚀 Generating main traffic...")
success = 0
fail = 0

for i in range(TOTAL_COMMANDS):
                                                                               
    if i % 50 == 0:
        active_user = "Admin1"
    else:
        active_user = random.choice(["Admin1", "User1"])
    
    session = sessions[active_user]
    
                               
    if active_user == "User1":
        cmd_type = "r"
    else:
        cmd_type = random.choices(["r", "w"], weights=[0.6, 0.4])[0]
    
                                                 
    payload = {
        "command_type": cmd_type,
        "device_id": DEVICE,
        "register": random.choice(REGISTERS),
        "priority": random.choice(["normal", "critical"]),
        "description": random_description(),
        "issued_by": active_user
    }
    if cmd_type == "w":
        payload["value"] = generate_value()
    
                  
    resp = session.post(COMMAND_URL, json=payload)
    
    if resp.status_code == 200:
        success += 1
        print(f"[{i+1:4d}] {active_user:6s} -> {cmd_type} | Reg {payload['register']} ✅")
    else:
        fail += 1
        print(f"[{i+1:4d}] {active_user:6s} -> {cmd_type} | Reg {payload['register']} ❌ {resp.status_code}")
    
                      
    if i % 100 < 20:
        time.sleep(random.uniform(0.05, 0.15))
    else:
        time.sleep(random.uniform(0.2, 0.5))

print(f"\n📊 Generation complete. Success: {success}, Failures: {fail}")