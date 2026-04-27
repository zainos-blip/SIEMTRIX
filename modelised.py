#!/usr/bin/env python3

from dotenv import load_dotenv
import os, re
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from typing import Optional
from enum import Enum, IntEnum
import pika, json, threading
import queue
from pathlib import Path
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
import urllib3, requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ALERTS_FILE = Path("alerts.json")
ACCEPTED_FILE = Path("accepted.json")
ML_OUTPUT_FILE = Path("ml_output.json")                     # <<< ML DECISION ENGINE

load_dotenv()

RABBIT_HOST = os.getenv("RABBIT_HOST")
RABBIT_PORT = int(os.getenv("RABBIT_PORT"))
RABBIT_USER = os.getenv("RABBIT_USER")
RABBIT_PASS = os.getenv("RABBIT_PASS")
RABBIT_QUEUE = os.getenv("RABBIT_QUEUE")
RABBIT_MAX_PRIORITY = int(os.getenv("RABBIT_MAX_PRIORITY"))
RABBIT_RESULT_QUEUE = os.getenv("RABBIT_RESULT_QUEUE")

# <<< ML DECISION ENGINE: new environment variables
ENABLE_ML_VALIDATION = os.getenv("ENABLE_ML_VALIDATION", "true").lower() == "true"
ML_IDS_URL = os.getenv("ML_IDS_URL", "http://localhost:5000/score")
ML_TIMEOUT = float(os.getenv("ML_TIMEOUT", "0.5"))
ML_FAIL_ACTION = os.getenv("ML_FAIL_ACTION", "allow")                   # allow or reject when ML call fails
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL")                           # reuse same HEC endpoint
SPLUNK_ML_TOKEN = os.getenv("SPLUNK_ML_TOKEN")                         # separate token for ML logs

app = FastAPI()


PENDING_READ_COMMANDS = {}

class FunctionCode(IntEnum):    
    READ_HOLDING_REGISTERS = 3
    WRITE_HOLDING_REGISTERS = 6

class Command_Type(str, Enum):
    write = "w"
    read = "r"

class Priority(str, Enum):
    normal = "normal"
    high = "critical"

class Command(BaseModel):
    command_type: Command_Type 
    device_id: str
    register_number: str
    value: Optional[int] = Field(None, ge=0, le=65535)
    priority: Priority 
    description: Optional[str] = Field(None, max_length=500)
    issued_by: str
    function_code: FunctionCode 
    command_id: str
    timestamp: datetime = Field(default_factory=datetime.now) 
    
    class Config:
        extra = "forbid"
        

# accepted command logging function
def log_accepted_commands(cmd: Command, read_value=None):
    cmd_data = jsonable_encoder(cmd)

    if isinstance(cmd_data.get("timestamp"), datetime):
        cmd_data["timestamp"] = cmd_data["timestamp"].isoformat()

    if read_value is not None:
        cmd_data["value"] = read_value
    

    entry = {
        "command": cmd_data,
        "decision": "approved"
    }

    success, error = send_to_splunk(entry, sourcetype="accepted_command", token=os.getenv("SPLUNK_HEC_TOKEN"))
    if not success:
        print(f" Failed to send to splunk: {error}")

    if ACCEPTED_FILE.exists():
        with open(ACCEPTED_FILE, "r+", encoding="utf-8") as f:
            try:
                logs = json.load(f)
            except json.JSONDecodeError:
                logs = []

            logs.append(entry)
            f.seek(0)
            f.truncate()
            json.dump(logs, f, indent=2)
    else:
        with open(ACCEPTED_FILE, "w", encoding="utf-8") as f:
            json.dump([entry], f, indent=2)



# alerts log function
def log_alert(cmd_data: dict, reason: str):
    cmd_data = jsonable_encoder(cmd_data)

    alert_entry = {
        "reason" : reason,
        "decision": "rejected",
        "command_data": cmd_data
    }
    splunk_payload = {
        "command_data": alert_entry["command_data"],
        "decision": "rejected"
    }

    success, error = send_to_splunk(splunk_payload, sourcetype="command_alert", token=os.getenv("SPLUNK_HEC_TOKEN"))

    if not success:
        print(f" Failed to send to splunk: {error}")
    
    if ALERTS_FILE.exists():
        with open(ALERTS_FILE, "r+", encoding="utf-8") as f:
            try:
                alerts = json.load(f)
            except json.JSONDecodeError:
                alerts = []
            alerts.append(alert_entry)
            f.seek(0) 
            json.dump(alerts, f, indent=2)
    else:
        with open(ALERTS_FILE, "w", encoding="utf-8") as f:
            json.dump([alert_entry], f, indent=2)


# sending logs to splunk indexer function – modified to accept optional token and index
def send_to_splunk(log_data: dict, sourcetype: str, token: str = None, index: str = None):
    url = os.getenv("SPLUNK_HEC_URL")
    # Use the provided token/index, otherwise fallback to env defaults
    if token is None:
        token = os.getenv("SPLUNK_HEC_TOKEN")
    if index is None:
        index = "dmz_validation"
    
    if not url or not token:
        return False, "Splunk HEC configuration missing"
    
    headers = {
        "Authorization": f"Splunk {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "host": "dmz-command-api",
        "source": "command_validation_api",
        "index": index,
        "event": log_data
    }

    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload), verify=False, timeout=1)
        if response.status_code in (200, 201):
            return True, None
        return False, f"Splunk HEC error: {response.status_code} {response.text}"
    except Exception as e:
        return False, str(e)


# <<< ML DECISION ENGINE: call ML inference service
def call_ml_inference(cmd: Command) -> Optional[dict]:
    """Send command data to ML endpoint. Returns dict with scores or None on failure."""
    payload = {
        "issued_by": cmd.issued_by,
        "command_type": cmd.command_type.value,
        "priority": cmd.priority.value,
        "register_number": cmd.register_number,
        "value": cmd.value if cmd.value is not None else 0,
        "function_code": cmd.function_code.value,
        "device_id": cmd.device_id,
        "description": cmd.description or "",
        "timestamp": cmd.timestamp.isoformat()
    }
    try:
        resp = requests.post(ML_IDS_URL, json=payload, timeout=ML_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "unsup_anomaly_score": data["unsup_anomaly_score"],
                    "unsup_is_anomaly": data["unsup_is_anomaly"],
                    "sup_attack_probability": data["sup_attack_probability"],
                    "sup_is_anomaly": data["sup_is_anomaly"]
                }
        print(f"ML inference returned {resp.status_code}: {resp.text}")
        return None
    except Exception as e:
        print(f"ML inference call failed: {e}")
        return None


def ml_decision(cmd: Command) -> tuple[str, str, Optional[dict]]:
    """
    Returns (verdict, reason, ml_result)
    verdict: "ALLOW" | "SUSPICIOUS" | "REJECT"
    """
    if not ENABLE_ML_VALIDATION:
        return "ALLOW", "ML validation disabled", None

    ml_result = call_ml_inference(cmd)
    if ml_result is None:
        if ML_FAIL_ACTION == "allow":
            return "ALLOW", "ML call failed, action=allow", None
        else:
            return "REJECT", "ML call failed, action=reject", None

    sup_anomaly = ml_result.get("sup_is_anomaly", False)
    unsup_anomaly = ml_result.get("unsup_is_anomaly", False)

    # Hybrid logic
    if sup_anomaly and unsup_anomaly:
        return "REJECT", "Both supervised and unsupervised models detected anomaly", ml_result
    elif sup_anomaly and not unsup_anomaly:
        return "REJECT", "Supervised model flagged anomaly", ml_result
    elif not sup_anomaly and unsup_anomaly:
        return "SUSPICIOUS", "Unsupervised anomaly (allowed but flagged for review)", ml_result
    else:
        return "ALLOW", "ML scores within normal range", ml_result


def log_ml_decision(cmd: Command, verdict: str, reason: str, ml_scores: Optional[dict]):
    """
    Log ML decision in flat, simplified format.
    """
    ts = cmd.timestamp.replace(tzinfo=timezone.utc).isoformat().replace('+00:00', 'Z')

    # Build the flat entry exactly as requested
    entry = {
        "id": cmd.command_id,
        "user": cmd.issued_by,
        "cmd": cmd.command_type.value,
        "reg": cmd.register_number,
        "val": cmd.value if cmd.value is not None else None,
        "ts": ts,
        "prob": round(ml_scores["sup_attack_probability"], 4) if ml_scores else None,
        "score": round(ml_scores["unsup_anomaly_score"], 4) if ml_scores else None,
        "decision": verdict,
        "reason": reason
    }

    # Append to local JSON file
    if ML_OUTPUT_FILE.exists():
        with open(ML_OUTPUT_FILE, "r+", encoding="utf-8") as f:
            try:
                logs = json.load(f)
            except json.JSONDecodeError:
                logs = []
            logs.append(entry)
            f.seek(0)
            f.truncate()
            json.dump(logs, f, indent=2)
    else:
        with open(ML_OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump([entry], f, indent=2)

    # Send to Splunk (flat payload)
    if SPLUNK_HEC_URL and SPLUNK_ML_TOKEN:
        send_to_splunk(entry, sourcetype="ml_decision", token=SPLUNK_ML_TOKEN, index="dmz_ml_ids")


ROLE_PERMISSIONS = {
    "Admin1": {Command_Type.read, Command_Type.write},
    "User1": {Command_Type.read}
}

# validated rules for the command
def validate_command(cmd: Command):
    if not re.match(r"^(HR_4000[1-9]|HR_4001[01])$", cmd.register_number):
        return False, "device should be within the range 'HR_40001 - HR_40011'"

    if not re.match(r"^PLC-00[1-9]$", cmd.device_id):
        return False, "device should follow 'PLC-<number> format"

    # Role based access control 
    if cmd.issued_by not in ROLE_PERMISSIONS:
        return False, f"Unkown User '{cmd.issued_by}'. Must be one of: {list(ROLE_PERMISSIONS.keys())}"

    allowed_commands = ROLE_PERMISSIONS[cmd.issued_by]
    
    if cmd.command_type.value not in allowed_commands:
        return False, f"'{cmd.issued_by}' does not have permission to send {cmd.command_type.value!r} commands"
    
    if not re.fullmatch(r"^CMD-[A-F0-9]{12}$", cmd.command_id):
        return False, "Invalid command_id format"

      # Additional validation for write commands
    if cmd.command_type == Command_Type.write and cmd.value is None:
        return False, "Value is required for write commands"
        
    # Additional validation for read commands (value should be None)
    if cmd.command_type == Command_Type.read and cmd.value is not None:
        return False, "Value should not be provided for read commands"
    
    # Function code check
    if cmd.command_type == Command_Type.read and cmd.function_code != FunctionCode.READ_HOLDING_REGISTERS:
        return False, f"Read commands must use the function code {FunctionCode.READ_HOLDING_REGISTERS}, not {cmd.function_code}"

    if cmd.command_type == Command_Type.write and cmd.function_code != FunctionCode.WRITE_HOLDING_REGISTERS:
        return False, f"Write commands must use the function code {FunctionCode.WRITE_HOLDING_REGISTERS}, not {cmd.function_code}"
 
    return True, None



def publish_to_rabbitmq(cmd: Command):
    credentials = pika.PlainCredentials(RABBIT_USER, RABBIT_PASS)
    parameters = pika.ConnectionParameters(host=RABBIT_HOST, port=RABBIT_PORT, credentials=credentials)
    conn = pika.BlockingConnection(parameters)
    ch = conn.channel()


    ch.queue_declare(
        queue=RABBIT_QUEUE,
        durable=True,
        arguments={"x-max-priority": RABBIT_MAX_PRIORITY}
    )

    cmd_dict = cmd.dict()

    if isinstance(cmd_dict.get("timestamp"), datetime):
        cmd_dict["timestamp"] = cmd_dict["timestamp"].isoformat()

    body = json.dumps(cmd_dict, ensure_ascii=False)

    priority_val = RABBIT_MAX_PRIORITY if cmd.priority == "critical" else 0
    properties = pika.BasicProperties(
        delivery_mode=2,
        priority=priority_val,
        content_type="application/json"
    )


    ch.basic_publish(
        exchange="",
        routing_key=RABBIT_QUEUE,
        body=body,
        properties=properties
    )

    conn.close()


def validate_plc_result(result: dict):
    # Check if it's a valid result structure
    if not isinstance(result, dict):
        return False
    
    # Check for command_id (required)
    if not result.get("command_id"):
        return False
    
    # Check status - accept both "success" and "ok"
    status = result.get("status")
    if status not in ["success", "ok"]:
        return False
    
    # Check value - handle both int and float, and allow None for errors
    value = result.get("value")
    if value is not None:
        try:
            # Convert to float first, then check range
            float_value = float(value)
            if not (0 <= float_value <= 65535):
                return False
        except (TypeError, ValueError):
            return False
    
    # Register number is optional in response
    # Type is optional in response
    
    return True

 
def consume_scada_results():
    credentials = pika.PlainCredentials(RABBIT_USER, RABBIT_PASS)
    parameters = pika.ConnectionParameters(host=RABBIT_HOST, port=RABBIT_PORT, credentials=credentials)
    conn = pika.BlockingConnection(parameters)
    ch = conn.channel()

    ch.queue_declare(
    queue=RABBIT_RESULT_QUEUE,
    durable=True,
    arguments={"x-max-priority": 10}
    )

    for method, properties, body in ch.consume(RABBIT_RESULT_QUEUE, auto_ack=True):
        try:
            data = json.loads(body)
            cmd_id = data.get("command_id")
            if cmd_id and cmd_id in PENDING_READ_COMMANDS and validate_plc_result(data):
                # Put SCADA response into the waiting queue
                PENDING_READ_COMMANDS[cmd_id].put(data)
        except Exception as e:
            print(f"Error processing SCADA result: {e}")


#-------------------------- BODY -----------------------------#
@app.exception_handler(RequestValidationError)
async def validation_log_alert(request: Request, exc: RequestValidationError):
    try:
        body = await request.json()
    except:
        body = {}

    alert_entry = {
        "timestamp": datetime.now().isoformat(),
        "reason": "Pydantic validation failed",
        "command_data": jsonable_encoder(body),
        "decision": "rejected"
    }

    if ALERTS_FILE.exists():
        with open(ALERTS_FILE, "r+", encoding="utf-8") as f:
            try:
                alerts = json.load(f)  
            except json.JSONDecodeError:
                alerts = []
            alerts.append(alert_entry)
            f.seek(0)
            f.truncate()
            json.dump(alerts, f, indent=2)
    else:
        with open(ALERTS_FILE, "w", encoding="utf-8") as f:
            json.dump([alert_entry], f, indent=2)
    
    splunk_payload = {
        "command_data": jsonable_encoder(body),
        "decision": "rejected"
    }

    success, error = send_to_splunk(
        splunk_payload,
        sourcetype="command_alert"
    )
    
    if not success:
        print(f"❌ Failed to send validation alert to Splunk: {error}")

    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "body": alert_entry["command_data"]}
    )




# Start it in startup event
@app.on_event("startup")
def start_background_tasks():
    # Start SCADA consumer (keep this - it's fine)
    t1 = threading.Thread(target=consume_scada_results, daemon=True)
    t1.start()
    


    print("✅ Command Validation API started successfully")


@app.get("/")
def root():
    return {"status": "COMMAND VALIDATION API RUNNING"}


# ----------- MAIN API ENDPOINT --------------
@app.post('/process_enqueue')
def process_q(cmd: Command):
    # 1. Basic rule-based validation (CV)
    ok, reason = validate_command(cmd)
    if not ok:
        log_alert(cmd, reason)
        raise HTTPException(status_code=400, detail=reason)

    # 2. ML decision engine (now follows table logic)
    decision, ml_reason, ml_scores = ml_decision(cmd)
    log_ml_decision(cmd, decision, ml_reason, ml_scores)

    # 3. Block if REJECT
    if decision == "REJECT":
        log_alert(cmd, ml_reason)
        raise HTTPException(status_code=403, detail=f"Command blocked by ML: {ml_reason}")

    # 4. For ALLOW – continue (including the "suspicious but allowed" case)
    if cmd.command_type == Command_Type.write:
        log_accepted_commands(cmd)

    # Register read command and wait for response
    if cmd.command_type == Command_Type.read:
        response_queue = queue.Queue()
        PENDING_READ_COMMANDS[cmd.command_id] = response_queue

    # Publish to RabbitMQ
    try:
        publish_to_rabbitmq(cmd)
    except Exception as e:
        if cmd.command_type == Command_Type.read:
            PENDING_READ_COMMANDS.pop(cmd.command_id, None)
        raise HTTPException(status_code=500, detail=f"Failed to publish to RabbitMQ: {e}")

    # Handle read response (if read command)
    if cmd.command_type == Command_Type.read:
        try:
            result = response_queue.get(timeout=8)
        except queue.Empty:
            PENDING_READ_COMMANDS.pop(cmd.command_id, None)
            raise HTTPException(status_code=504, detail="No response from HMI")

        PENDING_READ_COMMANDS.pop(cmd.command_id, None)
        log_accepted_commands(cmd, read_value=result.get("value"))

        return {
            "status": "success",
            "command_id": cmd.command_id,
            "value": result.get("value"),
            "timestamp": cmd.timestamp.isoformat()
        }

    # Write command response
    cmd_out = cmd.dict()
    if isinstance(cmd_out.get("timestamp"), datetime):
        cmd_out["timestamp"] = cmd_out["timestamp"].isoformat()

    return {"status": "accepted", "command": cmd_out}

#--- testing ----#
@app.get("/test-rabbitmq")
def test_rabbitmq_connection():
    """Test RabbitMQ connection directly"""
    try:
        print(f"🔧 Connection details:")
        print(f"   Host: {RABBIT_HOST}:{RABBIT_PORT}")
        print(f"   User: {RABBIT_USER}")
        print(f"   Queue: {RABBIT_QUEUE}")
        
        credentials = pika.PlainCredentials(RABBIT_USER, RABBIT_PASS)
        parameters = pika.ConnectionParameters(
            host=RABBIT_HOST,
            port=RABBIT_PORT,
            credentials=credentials,
            heartbeat=600,
            blocked_connection_timeout=300
        )
        
        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()
        
        # Test queue declaration
        channel.queue_declare(
            queue=RABBIT_QUEUE,
            durable=True,
            arguments={"x-max-priority": RABBIT_MAX_PRIORITY}
        )
        
        connection.close()
        
        return {
            "status": "success", 
            "message": "RabbitMQ connection successful!",
            "details": {
                "host": RABBIT_HOST,
                "port": RABBIT_PORT,
                "queue": RABBIT_QUEUE
            }
        }
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return {
            "status": "error",
            "message": str(e),
            "details": {
                "host": RABBIT_HOST,
                "port": RABBIT_PORT,
                "queue": RABBIT_QUEUE
            }
        }