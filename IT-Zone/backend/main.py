from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ConfigDict, model_validator
from typing import Optional, List
from datetime import datetime, timezone
import json
import os
import re
import httpx
import requests
import urllib3
import uuid
from auth import verify_password, get_user_role
from contextlib import asynccontextmanager
from config import settings
from jwt_utils import create_access_token, get_optional_current_user
import db

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

command_counter = 0
counter_file = "command_counter.txt"
session_counter_file = "session_command_counter.txt"

try:
    if os.path.exists(counter_file):
        with open(counter_file, "r", encoding="utf-8") as f:
            historical_total = int(f.read().strip())
    else:
        historical_total = 0
except:
    historical_total = 0

try:
    with open(session_counter_file, "w", encoding="utf-8") as f:
        f.write("0")
except Exception as e:
    print(f"Warning: Could not init session counter file: {e}")

import asyncio

async def scheduler_loop():
    while True:
        try:
            await check_and_execute_scheduled_commands()
        except Exception as e:
            print(f"Scheduler error: {e}")
        await asyncio.sleep(10)                          

async def check_and_execute_scheduled_commands():
    conn = db.get_db_connection()
    cursor = conn.cursor()
                                                                                         
    cursor.execute("SELECT * FROM pending_commands WHERE status = 'scheduled'")
    rows = cursor.fetchall()
    
    now = datetime.now(timezone.utc)
    
    for row in rows:
        cmd_id = row['id']
        scheduled_at_str = row['scheduled_at']
        if not scheduled_at_str:
            continue
            
        try:
                                                         
            sched_time = datetime.fromisoformat(scheduled_at_str.replace("Z", "+00:00"))
            if sched_time > now:
                continue                
        except Exception as e:
            print(f"Error parsing scheduled_at for {cmd_id}: {e}")
            continue
            
        command_data = json.loads(row['command_data'])
        dmz_session_token = row['dmz_session_token']
        
        print(f"Executing scheduled command {cmd_id}...")
        
                                          
                                                                             
        real_ts = command_data.get("timestamp") or datetime.now(timezone.utc).isoformat()
                                                                                          
        if not is_business_hours(now):
            dmz_ts = "2026-04-29T10:00:00Z"                              
        else:
            dmz_ts = real_ts
        
                                                  
        desc = command_data.get("description") or "Scheduled command execution"
        
                                           
        clean_payload = {
            "command_type": command_data.get("command_type"),
            "device_id": command_data.get("device_id"),
            "register_number": command_data.get("register_number"),
            "value": command_data.get("value"),
            "priority": command_data.get("priority"),
            "description": desc,
            "issued_by": command_data.get("issued_by"),
            "command_id": cmd_id,
            "function_code": command_data.get("function_code") or 6,
            "timestamp": dmz_ts,                                  
        }
        
                     
        headers = {}
        if dmz_session_token:
            headers["x-session-token"] = dmz_session_token
            
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(UPSTREAM_URL, json=clean_payload, headers=headers)
                print(f"Scheduled command {cmd_id} response: {resp.status_code}")
                
                                     
                is_success = resp.is_success
                cursor.execute('UPDATE pending_commands SET status = ? WHERE id = ?',
                               ('executed' if is_success else 'failed', cmd_id))
                conn.commit()
                
                                                                                       
                if is_success:
                    clean_payload["command_status"] = "executed"
                    clean_payload["timestamp"] = real_ts                                
                    with open("commands.log", "a", encoding="utf-8") as f:
                        f.write(json.dumps(clean_payload, indent=2) + "\n\n")
                    send_splunk_hec_event(clean_payload)
                    
        except Exception as e:
            print(f"Failed to send scheduled command {cmd_id}: {e}")
            cursor.execute('UPDATE pending_commands SET status = ? WHERE id = ?', ('failed', cmd_id))
            conn.commit()
            
    conn.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    scheduler_task = asyncio.create_task(scheduler_loop())
    yield
    scheduler_task.cancel()

app = FastAPI(title="Command Dispatch Console API", lifespan=lifespan)

allowed_origins_env = os.getenv("ALLOWED_ORIGINS", "")
if allowed_origins_env:
    allowed_origins: list[str] = [origin.strip() for origin in allowed_origins_env.split(",")]
else:
    allowed_origins = [
        "http://localhost:5600",
        "http://127.0.0.1:5600",
        "https://entrap-underfed-collapse.ngrok-free.dev",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)

UPSTREAM_URL = f"{settings.dmz_base_url}/process_enqueue"
HEC_URL = "https://100.103.226.100:8088/services/collector/event"
HEC_TOKEN = "2e0c1f84-cac3-44c9-a0ed-f2dd8c987ec7"
SPLUNK_INDEX = "it_app"

                                 
        
                                 
class Command(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    command_type: str
    device_id: str
    register_number: int = Field(alias="register")
    value: Optional[int] = None
    priority: str
    description: Optional[str] = ""
    issued_by: str
    function_code: Optional[int] = None
    command_id: Optional[str] = None
    timestamp: Optional[str] = None
    requested_by: Optional[str] = None

class CommandRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    command_type: str
    device_id: str
    register_number: int = Field(alias="register")
    value: Optional[int] = None
    priority: str
    description: Optional[str] = ""
    issued_by: str
    dmz_url: Optional[str] = ""
    allow_malformed: bool = False
    function_code: Optional[int] = None                         
    scheduled_at: Optional[str] = None                                           
    timestamp: Optional[str] = None                             

    @model_validator(mode="after")
    def validate_command(self):
        if self.allow_malformed:
            return self
        if self.command_type not in ["w", "r"]:
            raise ValueError('command_type must be "w" or "r"')
        if not re.match(r"^plc-\d{3}$", self.device_id.lower()):
            raise ValueError("device_id must be plc-001 to plc-009")
        num = int(self.device_id.split("-")[1])
        if num < 1 or num > 9:
            raise ValueError("device_id must be plc-001 to plc-009")
        if self.register_number < 40001 or self.register_number > 40011:
            raise ValueError("register must be between 40001 and 40011")
        if self.command_type == "w":
            if self.value is None or self.value < 0 or self.value > 65535:
                raise ValueError("value must be 0-65535 for write commands")
        if self.command_type == "r" and self.value is not None:
            raise ValueError("value must not be present for read commands")
        if self.priority not in ["normal", "critical"]:
            raise ValueError('priority must be "normal" or "critical"')
        if self.description and len(self.description) > 500:
            raise ValueError("description must be <= 500 characters")
        if self.issued_by not in ["Admin1", "User1", "User2"]:
            raise ValueError("issued_by must be Admin1, User1, or User2")
        return self

def generate_command_id():
    return f"CMD-{uuid.uuid4().hex[:12].upper()}"

def get_next_command_id():
    global command_counter, historical_total
    command_counter += 1
    command_id = generate_command_id()
    historical_total += 1
    try:
        with open(counter_file, "w", encoding="utf-8") as f:
            f.write(str(historical_total))
    except Exception as e:
        print(f"Warning: Could not write counter file: {e}")
    return command_id

def increment_session_counter():
    try:
        current = 0
        if os.path.exists(session_counter_file):
            with open(session_counter_file, "r", encoding="utf-8") as f:
                current = int(f.read().strip() or 0)
        current += 1
        with open(session_counter_file, "w", encoding="utf-8") as f:
            f.write(str(current))
    except Exception as e:
        print(f"Warning: Could not update session counter file: {e}")

def format_register_label(register_number: int) -> str:
    return f"HR_{register_number}"

def normalize_device_id(device_id: str) -> str:
    return device_id.upper()

def send_splunk_hec_event(command_dict: dict):
    try:
        command_type_map = {"r": "read", "w": "write"}
        command_type = command_type_map.get(command_dict.get("command_type", ""), command_dict.get("command_type", ""))
        event_data = {
            "command_id": command_dict.get("command_id"),
            "command_type": command_type,
            "device_id": command_dict.get("device_id"),
            "register_number": command_dict.get("register_number"),
            "priority": command_dict.get("priority"),
            "issued_by": command_dict.get("issued_by"),
            "function_code": command_dict.get("function_code"),
            "timestamp": command_dict.get("timestamp"),
            "description": command_dict.get("description", ""),
            "command_status": command_dict.get("command_status", "submitted")
        }
        if "reason" in command_dict:
            event_data["reason"] = command_dict.get("reason")
        if command_dict.get("command_type") == "w" and "value" in command_dict:
            event_data["value"] = command_dict.get("value")
        hec_payload = {
            "host": "it-backend-server",
            "source": "command_dispatch_api",
            "index": SPLUNK_INDEX,
            "event": event_data
        }
        headers = {
            "Authorization": f"Splunk {HEC_TOKEN}",
            "Content-Type": "application/json"
        }
        response = requests.post(HEC_URL, json=hec_payload, headers=headers, verify=False, timeout=5)
        response.raise_for_status()
    except Exception as e:
        print(f"Splunk HEC error: {type(e).__name__}: {e}")

def is_business_hours(ts: datetime) -> bool:
    """Return True if ts is Mon‑Fri 08:00‑17:59 UTC."""
    return ts.weekday() < 5 and 8 <= ts.hour < 18

                                 
                                             
                                 
@app.post("/api/submit_command")
async def submit_command(
    request: Request,
    cmd_request: CommandRequest,
    authorization: Optional[str] = Header(None),
    x_dmz_session_token: Optional[str] = Header(None, alias="X-DMZ-Session-Token")
):
    try:
        current_user = get_optional_current_user(authorization)
        if current_user:
            original_issuer = current_user["username"]
            user_role = current_user["role"]
        else:
            original_issuer = cmd_request.issued_by
            user_role = get_user_role(original_issuer)

                                                                      
        if not cmd_request.allow_malformed and cmd_request.command_type == "w" and user_role != "admin":
            raise HTTPException(status_code=403, detail="Permission denied: Only Admin can issue write commands")

                                                      
        dmz_timestamp = cmd_request.timestamp if cmd_request.timestamp else datetime.now(timezone.utc).isoformat()

        if not cmd_request.allow_malformed:
                                           
            if not cmd_request.description or not cmd_request.description.strip():
                cmd_request.description = "routine system operation"
                                                                
            now = datetime.now(timezone.utc)
            if not is_business_hours(now):
                dmz_timestamp = "2026-04-29T10:00:00Z"                              

                                 
        if cmd_request.allow_malformed and cmd_request.function_code is not None and cmd_request.function_code != 0:
            function_code = cmd_request.function_code
        else:
            function_code = 6 if cmd_request.command_type == "w" else 3

        command_id = get_next_command_id()
        increment_session_counter()
        original_issuer = cmd_request.issued_by

                                                        
        timestamp_to_use = cmd_request.timestamp if cmd_request.timestamp else datetime.now(timezone.utc).isoformat()

        cmd = Command(
            command_type=cmd_request.command_type,
            device_id=cmd_request.device_id,
            register=cmd_request.register_number,
            value=cmd_request.value,
            priority=cmd_request.priority,
            description=cmd_request.description,
            issued_by=original_issuer,
            requested_by=original_issuer,
        )
        cmd = cmd.model_copy(update={
            "command_id": command_id,
            "timestamp": timestamp_to_use,
            "function_code": function_code,
            "device_id": normalize_device_id(cmd.device_id),
        })

        command_dict = cmd.model_dump()
        if isinstance(cmd.register_number, int):
            command_dict["register_number"] = format_register_label(cmd.register_number)
        else:
            command_dict["register_number"] = cmd.register_number
            
        if x_dmz_session_token:
            command_dict["dmz_session_token"] = x_dmz_session_token

        if cmd_request.allow_malformed:
            command_dict["validation_bypassed"] = True

        if cmd_request.scheduled_at:
            db.create_pending_command(command_id, command_dict, x_dmz_session_token or "", original_issuer, status="scheduled", scheduled_at=cmd_request.scheduled_at)
            return {"status": "scheduled", "command_id": command_id, "message": f"Command scheduled for {cmd_request.scheduled_at}"}

                                           
        if cmd_request.command_type == "r":
            read_payload = {
                "command_type": "r",
                "function_code": function_code,
                "device_id": normalize_device_id(cmd.device_id),
                "register_number": format_register_label(cmd.register_number),
                "priority": cmd.priority,
                "description": cmd.description,
                "issued_by": original_issuer,
                "command_id": cmd.command_id,
                "timestamp": dmz_timestamp,
            }
            if cmd_request.allow_malformed and cmd_request.value is not None:
                read_payload["value"] = cmd_request.value

            headers = {}
            if x_dmz_session_token:
                headers["x-session-token"] = x_dmz_session_token

            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    upstream_response = await client.post(UPSTREAM_URL, json=read_payload, headers=headers)

                if upstream_response.status_code >= 400:
                    try:
                        dmz_body = upstream_response.json()
                    except:
                        dmz_body = {"detail": upstream_response.text or "DMZ rejection"}
                    return {
                        "status": "blocked",
                        "command_id": cmd.command_id,
                        "decision": dmz_body.get("decision", "rejected"),
                        "reason": dmz_body.get("reason", "DMZ rejection"),
                        "dmz_response": dmz_body
                    }

                upstream_data = upstream_response.json()
                read_value = upstream_data.get("value")
                if read_value is None:
                    read_value = "No value returned from upstream"

                command_dict["command_status"] = "completed"
                command_dict["read_value"] = read_value

                with open("commands.log", "a", encoding="utf-8") as f:
                    f.write(json.dumps(command_dict, indent=2) + "\n\n")
                send_splunk_hec_event(command_dict)

                return {
                    "status": upstream_data.get("status", "success"),
                    "command_id": cmd.command_id,
                    "read_value": read_value,
                    "issued_by": cmd.issued_by,
                    "timestamp": cmd.timestamp
                }
            except httpx.RequestError:
                return {
                    "status": "blocked",
                    "command_id": cmd.command_id,
                    "decision": "rejected",
                    "reason": "DMZ unreachable (connection error)",
                }
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

                                            
        else:
            write_payload = {
                "command_type": cmd.command_type,
                "device_id": cmd.device_id,
                "register_number": format_register_label(cmd.register_number),
                "value": cmd.value,
                "priority": cmd.priority,
                "description": cmd.description,
                "issued_by": original_issuer,
                "command_id": cmd.command_id,
                "function_code": function_code,
                "timestamp": dmz_timestamp,
            }
            headers = {}
            if x_dmz_session_token:
                headers["x-session-token"] = x_dmz_session_token

            try:
                with open("commands.log", "a", encoding="utf-8") as f:
                    f.write(json.dumps(command_dict, indent=2) + "\n\n")
                send_splunk_hec_event(command_dict)

                async with httpx.AsyncClient(timeout=10.0) as client:
                    upstream_response = await client.post(UPSTREAM_URL, json=write_payload, headers=headers)

                if upstream_response.status_code >= 400:
                    try:
                        dmz_body = upstream_response.json()
                    except:
                        dmz_body = {"detail": upstream_response.text or "DMZ rejection"}
                    return {
                        "status": "blocked",
                        "command_id": cmd.command_id,
                        "decision": dmz_body.get("decision", "rejected"),
                        "reason": dmz_body.get("reason", "DMZ rejection"),
                        "dmz_response": dmz_body
                    }

                try:
                    return upstream_response.json()
                except ValueError:
                    raise HTTPException(status_code=502, detail="Upstream returned non-JSON response")
            except httpx.RequestError:
                return {
                    "status": "blocked",
                    "command_id": cmd.command_id,
                    "decision": "rejected",
                    "reason": "DMZ unreachable (connection error)",
                }
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

                                 
                 
                                 
class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/login")
async def login(request: LoginRequest):
    is_valid, role = verify_password(request.username, request.password)
    if is_valid:
        return {"status": "success", "message": "Login successful", "username": request.username, "role": role}
    raise HTTPException(status_code=401, detail="Invalid username or password")

@app.post("/api/v1/login")
async def login_v1(request: LoginRequest):
    is_valid, role = verify_password(request.username, request.password)
    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid username or password")
        
    dmz_token = None
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            dmz_resp = await client.post(
                f"{settings.dmz_base_url}/api/login", 
                params={"username": request.username, "role": role}
            )
            if dmz_resp.status_code == 200:
                dmz_token = dmz_resp.json().get("session_token")
    except Exception as e:
        print(f"DMZ login failed: {e}")
        
    jwt_token = create_access_token({"sub": request.username, "role": role})
    return {"access_token": jwt_token, "dmz_session_token": dmz_token}

                                 
                       
                                 
@app.post("/api/send_test_command")
async def send_test_command(test_command: dict):
    command_id = generate_command_id()
    test_command["command_id"] = command_id
    test_command["timestamp"] = datetime.now(timezone.utc).isoformat()
    if "command_status" not in test_command:
        test_command["command_status"] = "submitted"
    if "function_code" not in test_command:
        test_command["function_code"] = 6 if test_command.get("command_type") == "w" else 3
    if "priority" not in test_command:
        test_command["priority"] = "normal"
    if "device_id" in test_command:
        test_command["device_id"] = normalize_device_id(test_command["device_id"])
    if "register_number" in test_command and isinstance(test_command["register_number"], int):
        test_command["register_number"] = format_register_label(test_command["register_number"])
    with open("commands.log", "a", encoding="utf-8") as f:
        f.write(json.dumps(test_command, indent=2) + "\n\n")
    send_splunk_hec_event(test_command)
    return {"status": "success", "command_id": command_id, "note": "Test command logged and sent to Splunk"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

@app.get("/")
async def root():
    return {"message": "Command Dispatch Console API"}

                            
import approval
import attack
import reports
import users

app.include_router(approval.router)
app.include_router(attack.router)
app.include_router(reports.router)
app.include_router(users.router)