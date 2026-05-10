#!/usr/bin/env python3

from dotenv import load_dotenv
import os, re, time, threading
from collections import deque
from fastapi import FastAPI, HTTPException, Request, Header
from pydantic import BaseModel, Field
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List
from enum import Enum, IntEnum
import pika, json
import queue
from pathlib import Path
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
import urllib3, requests
from mitreattack.stix20 import MitreAttackData
from fastapi.middleware.cors import CORSMiddleware
import uuid
import socket

# Load STIX file
MITRE_ATTACK_FILE = "ics-attack.json"
mitre_data = MitreAttackData(MITRE_ATTACK_FILE)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ALERTS_FILE = Path("alerts.json")
ACCEPTED_FILE = Path("accepted.json")
ML_OUTPUT_FILE = Path("ml_output.json")
REPLAY_HISTORY_FILE = Path("replay_history.json")

load_dotenv()

# ---------- RabbitMQ ----------
RABBIT_HOST = os.getenv("RABBIT_HOST")
RABBIT_PORT = int(os.getenv("RABBIT_PORT"))
RABBIT_USER = os.getenv("RABBIT_USER")
RABBIT_PASS = os.getenv("RABBIT_PASS")
RABBIT_QUEUE = os.getenv("RABBIT_QUEUE")
RABBIT_MAX_PRIORITY = int(os.getenv("RABBIT_MAX_PRIORITY"))
RABBIT_RESULT_QUEUE = os.getenv("RABBIT_RESULT_QUEUE")

# ---------- ML ----------
ENABLE_ML_VALIDATION = os.getenv("ENABLE_ML_VALIDATION", "true").lower() == "true"
ML_IDS_URL = os.getenv("ML_IDS_URL", "http://localhost:5000/score")
ML_TIMEOUT = float(os.getenv("ML_TIMEOUT", "0.5"))
ML_FAIL_ACTION = os.getenv("ML_FAIL_ACTION", "allow")

# ---------- Splunk ----------
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL")
SPLUNK_ML_TOKEN = os.getenv("SPLUNK_ML_TOKEN")

# ---------- Static rule: replay detection (persistent) ----------
REPLAY_ENABLED = os.getenv("REPLAY_ENABLED", "true").lower() == "true"
REPLAY_MAX_IDS = int(os.getenv("REPLAY_MAX_IDS", "2000"))

# ---------- Static rule: rate limiter ----------
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_MAX", "10"))
RATE_LIMIT_WINDOW = float(os.getenv("RATE_LIMIT_WINDOW", "1.0"))
user_timestamps = {}
rate_limiter_lock = threading.Lock()

# ---------- MITRE REJECTION CONFIG ----------
REJECT_ON_MITRE = os.getenv("REJECT_ON_MITRE", "true").lower() == "true"

# ---------- NEW: Automatic reset on startup ----------
RESET_ON_STARTUP = os.getenv("RESET_ON_STARTUP", "true").lower() == "true"
RESET_LOGS_ON_STARTUP = os.getenv("RESET_LOGS_ON_STARTUP", "false").lower() == "true"

# ---------- NEW: Session management ----------
sessions: Dict[str, dict] = {}
sessions_lock = threading.Lock()

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PENDING_READ_COMMANDS = {}

# ---------- JSON file helpers ----------
def load_json_file(file_path: Path) -> list:
    if not file_path.exists():
        return []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, IOError):
        return []

def find_decision_by_command_id(command_id: str) -> dict:
    alerts = load_json_file(ALERTS_FILE)
    for entry in alerts:
        if entry.get("command_id") == command_id:
            return {"decision": "rejected", "reason": entry.get("reason", "Unknown reason"), "details": entry}
    accepted = load_json_file(ACCEPTED_FILE)
    for entry in accepted:
        if entry.get("command_id") == command_id:
            return {"decision": "approved", "reason": entry.get("reason", "Command accepted"), "details": entry}
    return {"decision": "not_found", "reason": "Command ID not found in logs"}

# Build technique map
def build_technique_map(stix_file):
    with open(stix_file, 'r') as f:
        bundle = json.load(f)
    tech_map = {}
    for obj in bundle.get('objects', []):
        if obj.get('type') == 'attack-pattern':
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    ext_id = ref.get('external_id')
                    if ext_id:
                        tech_map[ext_id] = {
                            'technique_id': ext_id,
                            'technique_name': obj.get('name', ext_id),
                            'description': obj.get('description', ''),
                            'tactics': [phase['phase_name'] for phase in obj.get('kill_chain_phases', [])],
                            'severity': 'high' if ext_id in {'T0855','T0885','T0889'} else 'medium'
                        }
    return tech_map

TECHNIQUE_MAP = build_technique_map(MITRE_ATTACK_FILE)

# Replay history
def load_replay_history() -> deque:
    if REPLAY_HISTORY_FILE.exists():
        try:
            data = json.loads(REPLAY_HISTORY_FILE.read_text())
            return deque(data, maxlen=REPLAY_MAX_IDS)
        except Exception:
            pass
    return deque(maxlen=REPLAY_MAX_IDS)

def save_replay_history(history: deque):
    try:
        with open(REPLAY_HISTORY_FILE, "w") as f:
            json.dump(list(history), f)
    except Exception:
        pass

def reset_session(clear_logs: bool = False):
    global RECENT_IDS, user_timestamps, sessions
    RECENT_IDS.clear()
    if REPLAY_HISTORY_FILE.exists():
        REPLAY_HISTORY_FILE.unlink()
    user_timestamps.clear()
    if clear_logs:
        with sessions_lock:
            sessions.clear()
        for file in [ALERTS_FILE, ACCEPTED_FILE, ML_OUTPUT_FILE]:
            if file.exists():
                file.unlink()

RECENT_IDS = load_replay_history()

# Data models
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
    value: Optional[int] = Field(None, ge=0)
    priority: Priority
    description: Optional[str] = Field(None, max_length=500)
    issued_by: str
    function_code: FunctionCode
    command_id: str
    timestamp: datetime = Field(default_factory=datetime.now)

    class Config:
        extra = "forbid"

# MITRE detection
def detect_mitre_techniques(cmd: Command) -> List[Dict]:
    technique_ids = set()
    user = cmd.issued_by
    cmd_type = cmd.command_type.value
    reg = cmd.register_number
    value = cmd.value
    func = cmd.function_code.value
    device = cmd.device_id
    desc = cmd.description or ""
    desc_len = len(desc.strip())
    desc_susp = any(kw in desc.lower() for kw in {
        'shutdown','delete','exec','cmd','exploit','inject',
        'override','shell','sudo','rm -rf','format','kill',
        'disable','malware','backdoor'
    })
    ts = cmd.timestamp
    hour = ts.hour
    day = ts.weekday()

    if user == 'User1' and cmd_type == 'w':
        technique_ids.add('T0855')
    if not user:
        technique_ids.add('T0855')
    if cmd_type == 'r' and value is not None and value != 0:
        technique_ids.add('T0855')
    if func not in (3, 6) and cmd_type in ('r', 'w'):
        technique_ids.add('T0855')

    if value is not None and (value < 0 or value > 65535):
        technique_ids.add('T0885')
    if not re.match(r'^HR_(\d+)$', reg):
        pass
    else:
        reg_num = int(re.search(r'\d+', reg).group())
        if reg_num == 0 or reg_num > 65535:
            technique_ids.add('T0885')
    if cmd_type == 'w' and (value is None or value == -9999):
        technique_ids.add('T0885')

    if not re.match(r'^HR_4000[1-9]|HR_4001[01]$', reg):
        technique_ids.add('T0884')
    if device.upper() not in {'PLC-001'}:
        technique_ids.add('T0884')

    if user not in {'Admin1', 'User1', ''}:
        technique_ids.add('T0859')
        technique_ids.add('T1078')
    if hour < 6 or hour >= 22 or day >= 5:
        technique_ids.add('T1078')

    if cmd.priority.value not in {'normal', 'critical'}:
        technique_ids.add('T0805')
    if not re.match(r'^HR_\d+$', reg):
        technique_ids.add('T0805')

    if desc_len > 200:
        technique_ids.add('T0889')
    if desc_susp:
        technique_ids.add('T0889')

    if func in {1, 2, 4, 5, 15, 16}:
        technique_ids.add('T0847')

    result = []
    for tid in sorted(technique_ids):
        if tid in TECHNIQUE_MAP:
            tech = TECHNIQUE_MAP[tid]
            description = tech['description']
            if len(description) > 300:
                description = description[:300] + '...'
            result.append({
                'technique_id': tid,
                'technique_name': tech['technique_name'],
                'description': description,
                'tactics': tech['tactics'],
                'severity': tech['severity']
            })
        else:
            result.append({
                'technique_id': tid,
                'technique_name': tid,
                'description': 'ICS attack technique (description not found)',
                'tactics': [],
                'severity': 'medium'
            })
    return result

# Logging
def send_to_splunk(log_data: dict, sourcetype: str, token: str = None, index: str = None):
    url = os.getenv("SPLUNK_HEC_URL")
    if token is None:
        token = os.getenv("SPLUNK_HEC_TOKEN")
    if index is None:
        index = "dmz_validation"
    if not url or not token:
        return False, "Splunk HEC configuration missing"
    headers = {"Authorization": f"Splunk {token}", "Content-Type": "application/json"}
    payload = {"host": "dmz-command-api", "source": "command_validation_api", "index": index, "event": log_data}
    try:
        resp = requests.post(url, headers=headers, data=json.dumps(payload), verify=False, timeout=5)
        if resp.status_code in (200, 201):
            return True, None
        return False, f"Splunk HEC error: {resp.status_code} {resp.text}"
    except Exception as e:
        print(f"-----SPLUNK ERROR------- {e}")
        return False, str(e)

def flatten_command(cmd: Command, read_value=None) -> dict:
    return {
        "command_id": cmd.command_id,
        "command_type": cmd.command_type.value,
        "device_id": cmd.device_id,
        "register_number": cmd.register_number,
        "priority": cmd.priority.value,
        "description": cmd.description,
        "issued_by": cmd.issued_by,
        "function_code": cmd.function_code.value,
        "timestamp": cmd.timestamp.isoformat() if cmd.timestamp else None,
        "value": read_value if read_value is not None else cmd.value
    }

def log_accepted_commands(cmd: Command, read_value=None, mitre_tags: Optional[List[Dict]] = None):
    flat_data = flatten_command(cmd, read_value)
    entry = {"decision": "approved", **flat_data}
    if mitre_tags:
        entry["mitre_techniques"] = mitre_tags
    send_to_splunk(entry, sourcetype="accepted_command")
    if ACCEPTED_FILE.exists():
        with open(ACCEPTED_FILE, "r+", encoding="utf-8") as f:
            try: logs = json.load(f)
            except json.JSONDecodeError: logs = []
            logs.append(entry)
            f.seek(0); f.truncate(); json.dump(logs, f, indent=2)
    else:
        with open(ACCEPTED_FILE, "w", encoding="utf-8") as f:
            json.dump([entry], f, indent=2)

def log_alert(cmd_data, reason: str, mitre_tags: Optional[List[Dict]] = None):
    if isinstance(cmd_data, Command):
        flat_data = flatten_command(cmd_data)
    else:
        if "command_data" in cmd_data:
            flat_data = {k: v for k, v in cmd_data.items() if k != "command_data"}
            flat_data.update(cmd_data["command_data"])
        else:
            flat_data = dict(cmd_data)
    alert_entry = {"reason": reason, "decision": "rejected", **flat_data}
    if mitre_tags:
        alert_entry["mitre_techniques"] = mitre_tags
    send_to_splunk(alert_entry, sourcetype="command_alert")
    if ALERTS_FILE.exists():
        with open(ALERTS_FILE, "r+", encoding="utf-8") as f:
            try: alerts = json.load(f)
            except json.JSONDecodeError: alerts = []
            alerts.append(alert_entry)
            f.seek(0); f.truncate(); json.dump(alerts, f, indent=2)
    else:
        with open(ALERTS_FILE, "w", encoding="utf-8") as f:
            json.dump([alert_entry], f, indent=2)

# ML functions
def call_ml_inference(cmd: Command) -> Optional[dict]:
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

def ml_decision(cmd: Command) -> tuple:
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
    if sup_anomaly and unsup_anomaly:
        return "REJECT", "Both supervised and unsupervised models detected anomaly", ml_result
    elif sup_anomaly and not unsup_anomaly:
        return "REJECT", "Supervised model flagged anomaly", ml_result
    elif not sup_anomaly and unsup_anomaly:
        return "SUSPICIOUS", "Unsupervised anomaly (allowed but flagged for review)", ml_result
    else:
        return "ALLOW", "ML scores within normal range", ml_result

def log_ml_decision(cmd: Command, verdict: str, reason: str, ml_scores: Optional[dict], mitre_tags: Optional[List[Dict]] = None):
    ts = cmd.timestamp.replace(tzinfo=timezone.utc).isoformat().replace('+00:00', 'Z')
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
    if mitre_tags:
        entry["mitre_techniques"] = mitre_tags
    if ML_OUTPUT_FILE.exists():
        with open(ML_OUTPUT_FILE, "r+", encoding="utf-8") as f:
            try: logs = json.load(f)
            except json.JSONDecodeError: logs = []
            logs.append(entry)
            f.seek(0); f.truncate(); json.dump(logs, f, indent=2)
    else:
        with open(ML_OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump([entry], f, indent=2)
    if SPLUNK_HEC_URL and SPLUNK_ML_TOKEN:
        send_to_splunk(entry, sourcetype="ml_decision", token=SPLUNK_ML_TOKEN, index="dmz_ml_ids")

# Static validation
ROLE_PERMISSIONS = {
    "Admin1": {Command_Type.read, Command_Type.write},
    "User1": {Command_Type.read}
}

def static_rules_check(cmd: Command) -> tuple[bool, str]:
    if not re.match(r"^(HR_4000[1-9]|HR_4001[01])$", cmd.register_number):
        return False, "register_number should be within 'HR_40001 - HR_40011'"
    if not re.match(r"^PLC-00[1-9]$", cmd.device_id):
        return False, "device_id should follow 'PLC-00X' format"
    if cmd.issued_by not in ROLE_PERMISSIONS:
        return False, f"Unknown User '{cmd.issued_by}'. Must be one of: {list(ROLE_PERMISSIONS.keys())}"
    allowed_commands = ROLE_PERMISSIONS[cmd.issued_by]
    if cmd.command_type.value not in allowed_commands:
        return False, f"'{cmd.issued_by}' does not have permission to send {cmd.command_type.value!r} commands"
    if not re.fullmatch(r"^CMD-[A-F0-9]{12}$", cmd.command_id):
        return False, "Invalid command_id format"
    if cmd.command_type == Command_Type.write and cmd.value is None:
        return False, "Value is required for write commands"
    if cmd.command_type == Command_Type.read and cmd.value is not None:
        return False, "Value should not be provided for read commands"
    if cmd.command_type == Command_Type.read and cmd.function_code != FunctionCode.READ_HOLDING_REGISTERS:
        return False, f"Read commands must use function code 3, not {cmd.function_code}"
    if cmd.command_type == Command_Type.write and cmd.function_code != FunctionCode.WRITE_HOLDING_REGISTERS:
        return False, f"Write commands must use function code 6, not {cmd.function_code}"

    if REPLAY_ENABLED:
        if cmd.command_id in RECENT_IDS:
            return False, f"Duplicate command_id (replay): {cmd.command_id}"
        RECENT_IDS.append(cmd.command_id)
        save_replay_history(RECENT_IDS)

    if RATE_LIMIT_ENABLED:
        with rate_limiter_lock:
            now = time.time()
            user = cmd.issued_by or "unknown"
            if user not in user_timestamps:
                user_timestamps[user] = deque()
            q = user_timestamps[user]
            while q and now - q[0] > RATE_LIMIT_WINDOW:
                q.popleft()
            current = len(q)
            if current >= RATE_LIMIT_MAX:
                return False, f"Rate limit exceeded: {RATE_LIMIT_MAX} requests per {RATE_LIMIT_WINDOW}s"
            q.append(now)
    return True, None

def check_border_value(cmd: Command) -> Optional[Dict]:
    if cmd.command_type == Command_Type.write and cmd.value is not None and cmd.value > 65535:
        return {
            "technique_id": "T1202",
            "technique_name": "Indirect Command Execution",
            "description": f"Border value {cmd.value} exceeds 16‑bit Modbus range (0‑65535). Potential overflow or malicious intent.",
            "tactics": ["Execution", "Persistence"],
            "severity": "medium"
        }
    return None

# RabbitMQ helpers with timeout
def publish_to_rabbitmq(cmd: Command):
    """Publish command to RabbitMQ with connection timeout."""
    try:
        credentials = pika.PlainCredentials(RABBIT_USER, RABBIT_PASS)
        parameters = pika.ConnectionParameters(
            host=RABBIT_HOST,
            port=RABBIT_PORT,
            credentials=credentials,
            socket_timeout=5,          # seconds for socket operations
            connection_attempts=1,
            retry_delay=0
        )
        conn = pika.BlockingConnection(parameters)
        ch = conn.channel()
        ch.queue_declare(queue=RABBIT_QUEUE, durable=True, arguments={"x-max-priority": RABBIT_MAX_PRIORITY})
        cmd_dict = cmd.dict()
        if isinstance(cmd_dict.get("timestamp"), datetime):
            cmd_dict["timestamp"] = cmd_dict["timestamp"].isoformat()
        body = json.dumps(cmd_dict, ensure_ascii=False)
        priority_val = RABBIT_MAX_PRIORITY if cmd.priority == "critical" else 0
        properties = pika.BasicProperties(delivery_mode=2, priority=priority_val, content_type="application/json")
        ch.basic_publish(exchange="", routing_key=RABBIT_QUEUE, body=body, properties=properties)
        conn.close()
    except (pika.exceptions.AMQPConnectionError, socket.timeout, Exception) as e:
        print(f"RabbitMQ publish error: {e}")
        raise Exception(f"Failed to connect/publish to RabbitMQ: {e}")

def validate_plc_result(result: dict):
    if not isinstance(result, dict) or not result.get("command_id"):
        return False
    status = result.get("status")
    if status not in ["success", "ok"]:
        return False
    value = result.get("value")
    if value is not None:
        try:
            if not (0 <= float(value) <= 65535):
                return False
        except (TypeError, ValueError):
            return False
    return True

def consume_scada_results():
    while True:
        try:
            credentials = pika.PlainCredentials(RABBIT_USER, RABBIT_PASS)
            parameters = pika.ConnectionParameters(
                host=RABBIT_HOST,
                port=RABBIT_PORT,
                credentials=credentials,
                socket_timeout=5
            )
            conn = pika.BlockingConnection(parameters)
            ch = conn.channel()
            ch.queue_declare(queue=RABBIT_RESULT_QUEUE, durable=True, arguments={"x-max-priority": 10})
            for method, properties, body in ch.consume(RABBIT_RESULT_QUEUE, auto_ack=True):
                try:
                    data = json.loads(body)
                    cmd_id = data.get("command_id")
                    if cmd_id and cmd_id in PENDING_READ_COMMANDS and validate_plc_result(data):
                        PENDING_READ_COMMANDS[cmd_id].put(data)
                except Exception as e:
                    print(f"Error processing SCADA result: {e}")
        except Exception as e:
            print(f"RabbitMQ consumer failed, retrying in 5s: {e}")
            time.sleep(5)

# Exception handler
@app.exception_handler(RequestValidationError)
async def validation_log_alert(request: Request, exc: RequestValidationError):
    try:
        body = await request.json()
    except:
        body = {}
    flat_alert = {
        "timestamp": datetime.now().isoformat(),
        "reason": "Pydantic validation failed",
        "decision": "rejected",
        **jsonable_encoder(body)
    }
    if ALERTS_FILE.exists():
        with open(ALERTS_FILE, "r+", encoding="utf-8") as f:
            try: alerts = json.load(f)
            except json.JSONDecodeError: alerts = []
            alerts.append(flat_alert)
            f.seek(0); f.truncate(); json.dump(alerts, f, indent=2)
    else:
        with open(ALERTS_FILE, "w", encoding="utf-8") as f:
            json.dump([flat_alert], f, indent=2)
    send_to_splunk(flat_alert, sourcetype="command_alert")
    return JSONResponse(status_code=422, content={"detail": exc.errors(), "body": body})

# Session cleanup
SESSION_TIMEOUT_SECONDS = 30 * 60
def session_cleanup_daemon():
    while True:
        time.sleep(60)
        now = datetime.now(timezone.utc)
        expired = []
        with sessions_lock:
            for token, sess in sessions.items():
                last_activity = sess.get("last_activity")
                if last_activity is None:
                    continue
                if isinstance(last_activity, str):
                    try:
                        last_activity = datetime.fromisoformat(last_activity)
                    except:
                        continue
                if (now - last_activity).total_seconds() > SESSION_TIMEOUT_SECONDS:
                    expired.append(token)
            for token in expired:
                del sessions[token]
        if expired:
            print(f"🧹 Cleaned {len(expired)} expired session(s)")

# Session endpoints
@app.post("/api/login")
async def login(username: str = "operator", role: str = "tester"):
    token = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    with sessions_lock:
        sessions[token] = {
            "user": username,
            "role": role,
            "commands": [],
            "created_at": now.isoformat(),
            "last_activity": now
        }
    return {"status": "success", "session_token": token, "user": username}

@app.get("/api/session/commands")
async def get_session_commands(x_session_token: str = Header(...)):
    with sessions_lock:
        if x_session_token not in sessions:
            raise HTTPException(status_code=401, detail="Invalid or expired session token")
        sessions[x_session_token]["last_activity"] = datetime.now(timezone.utc)
        return sessions[x_session_token]["commands"]

@app.post("/api/session/clear")
async def clear_session(x_session_token: str = Header(...)):
    with sessions_lock:
        if x_session_token not in sessions:
            raise HTTPException(status_code=401, detail="Invalid session token")
        sessions[x_session_token]["last_activity"] = datetime.now(timezone.utc)
        sessions[x_session_token]["commands"] = []
    return {"status": "session cleared"}

@app.post("/reset_session")
def reset_session_endpoint(clear_logs: bool = False):
    reset_session(clear_logs)
    return {
        "status": "session reset",
        "replay_history": "cleared",
        "rate_limiter": "cleared",
        "log_files": "deleted" if clear_logs else "preserved",
        "sessions_cleared": clear_logs
    }

@app.on_event("startup")
def startup_event():
    if RESET_ON_STARTUP:
        reset_session(clear_logs=RESET_LOGS_ON_STARTUP)
        print("🔁 Automatic session reset performed on startup")
    threading.Thread(target=session_cleanup_daemon, daemon=True).start()
    threading.Thread(target=consume_scada_results, daemon=True).start()
    print("✅ Command Validation API started successfully")
    print(f"↺ Replay detection: {'ON' if REPLAY_ENABLED else 'OFF'}")
    print(f"⏱️  Rate limiter: {'ON' if RATE_LIMIT_ENABLED else 'OFF'}")
    print("🕒 Session timeout: 30 minutes")

@app.get("/")
def root():
    return {"status": "COMMAND VALIDATION API RUNNING"}

# Main endpoint - MODIFIED with timeout handling
@app.post('/process_enqueue')
def process_q(cmd: Command, x_session_token: Optional[str] = Header(None)):
    session_cmd_entry = None
    if x_session_token:
        with sessions_lock:
            session = sessions.get(x_session_token)
            if session:
                session["last_activity"] = datetime.now(timezone.utc)
                session_cmd_entry = {
                    "command_id": cmd.command_id,
                    "command_type": cmd.command_type.value,
                    "device_id": cmd.device_id,
                    "register": cmd.register_number,
                    "value": None,
                    "timestamp": cmd.timestamp.isoformat(),
                    "status": "submitted",
                    "dmz_decision": None,
                    "ml_decision": None,
                    "ml_score": None,
                    "ml_reason": None,
                    "mitre_techniques": None
                }
                session["commands"].append(session_cmd_entry)
    
    ok, reason = static_rules_check(cmd)
    mitre_tags = detect_mitre_techniques(cmd)
    
    if not ok:
        if session_cmd_entry:
            session_cmd_entry["status"] = "dmz_rejected"
            session_cmd_entry["dmz_decision"] = "rejected"
            session_cmd_entry["mitre_techniques"] = mitre_tags
            session_cmd_entry["rejection_reason"] = reason
        log_alert(cmd, reason, mitre_tags=mitre_tags)
        raise HTTPException(status_code=400, detail=reason)

    if REJECT_ON_MITRE and mitre_tags:
        mitre_ids = [t['technique_id'] for t in mitre_tags]
        mitre_names = [t['technique_name'] for t in mitre_tags]
        reason = f"MITRE ATT&CK technique detected and blocked: {', '.join(mitre_ids)} - {', '.join(mitre_names)}"
        if session_cmd_entry:
            session_cmd_entry["status"] = "rejected_by_mitre"
            session_cmd_entry["dmz_decision"] = "rejected"
            session_cmd_entry["mitre_techniques"] = mitre_tags
            session_cmd_entry["rejection_reason"] = reason
        log_alert(cmd, reason, mitre_tags=mitre_tags)
        raise HTTPException(status_code=403, detail=reason)

    border_mitre = check_border_value(cmd)
    if border_mitre:
        mitre_tags.append(border_mitre)
        if not REJECT_ON_MITRE:
            log_alert(cmd, f"Border value {cmd.value} > 65535 (review required)", mitre_tags=mitre_tags)

    if session_cmd_entry:
        session_cmd_entry["status"] = "dmz_approved"
        session_cmd_entry["dmz_decision"] = "approved"
        session_cmd_entry["mitre_techniques"] = mitre_tags

    decision, ml_reason, ml_scores = ml_decision(cmd)
    log_ml_decision(cmd, decision, ml_reason, ml_scores, mitre_tags=mitre_tags)

    if session_cmd_entry:
        session_cmd_entry["ml_decision"] = decision.lower()
        session_cmd_entry["ml_score"] = round(ml_scores["unsup_anomaly_score"], 4) if ml_scores else None
        session_cmd_entry["ml_reason"] = ml_reason
        if decision == "REJECT":
            session_cmd_entry["status"] = "rejected_by_ml"
        elif decision == "SUSPICIOUS":
            session_cmd_entry["status"] = "suspicious"
        else:
            session_cmd_entry["status"] = "ml_approved"

    if decision == "REJECT":
        log_alert(cmd, ml_reason, mitre_tags=mitre_tags)
        raise HTTPException(status_code=403, detail=f"Command blocked by ML: {ml_reason}")

    if cmd.command_type == Command_Type.write:
        log_accepted_commands(cmd, mitre_tags=mitre_tags)
        if session_cmd_entry:
            session_cmd_entry["status"] = "accepted"
            session_cmd_entry["value"] = cmd.value

    if cmd.command_type == Command_Type.read:
        response_queue = queue.Queue()
        PENDING_READ_COMMANDS[cmd.command_id] = response_queue

    try:
        publish_to_rabbitmq(cmd)
    except Exception as e:
        if cmd.command_type == Command_Type.read:
            PENDING_READ_COMMANDS.pop(cmd.command_id, None)
        if session_cmd_entry:
            session_cmd_entry["status"] = "publish_failed"
        # Now raise HTTP 500 quickly instead of hanging
        raise HTTPException(status_code=500, detail=f"Failed to publish to RabbitMQ: {e}")

    if session_cmd_entry:
        session_cmd_entry["status"] = "executed"

    if cmd.command_type == Command_Type.read:
        try:
            result = response_queue.get(timeout=8)
        except queue.Empty:
            PENDING_READ_COMMANDS.pop(cmd.command_id, None)
            if session_cmd_entry:
                session_cmd_entry["status"] = "timeout"
            raise HTTPException(status_code=504, detail="No response from HMI")
        PENDING_READ_COMMANDS.pop(cmd.command_id, None)
        log_accepted_commands(cmd, read_value=result.get("value"), mitre_tags=mitre_tags)
        if session_cmd_entry:
            session_cmd_entry["value"] = result.get("value")
            session_cmd_entry["status"] = "completed"
        return {
            "status": "success",
            "command_id": cmd.command_id,
            "value": result.get("value"),
            "timestamp": cmd.timestamp.isoformat()
        }

    cmd_out = cmd.dict()
    if isinstance(cmd_out.get("timestamp"), datetime):
        cmd_out["timestamp"] = cmd_out["timestamp"].isoformat()
    return {"status": "accepted", "command": cmd_out}

@app.get("/test-rabbitmq")
def test_rabbitmq_connection():
    try:
        credentials = pika.PlainCredentials(RABBIT_USER, RABBIT_PASS)
        parameters = pika.ConnectionParameters(host=RABBIT_HOST, port=RABBIT_PORT,
                                               credentials=credentials, heartbeat=600,
                                               blocked_connection_timeout=300, socket_timeout=5)
        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()
        channel.queue_declare(queue=RABBIT_QUEUE, durable=True,
                              arguments={"x-max-priority": RABBIT_MAX_PRIORITY})
        connection.close()
        return {"status": "success", "message": "RabbitMQ connection successful!",
                "details": {"host": RABBIT_HOST, "port": RABBIT_PORT, "queue": RABBIT_QUEUE}}
    except Exception as e:
        return {"status": "error", "message": str(e),
                "details": {"host": RABBIT_HOST, "port": RABBIT_PORT, "queue": RABBIT_QUEUE}}

# Frontend endpoints
@app.get("/api/alerts")
async def get_alerts(limit: int = 100, offset: int = 0):
    alerts = load_json_file(ALERTS_FILE)
    alerts.reverse()
    paginated = alerts[offset:offset+limit]
    return {"total": len(alerts), "limit": limit, "offset": offset, "data": paginated}

@app.get("/api/accepted")
async def get_accepted(limit: int = 100, offset: int = 0):
    accepted = load_json_file(ACCEPTED_FILE)
    accepted.reverse()
    paginated = accepted[offset:offset+limit]
    return {"total": len(accepted), "limit": limit, "offset": offset, "data": paginated}

@app.get("/api/ml_output")
async def get_ml_output(limit: int = 100, offset: int = 0):
    ml_data = load_json_file(ML_OUTPUT_FILE)
    ml_data.reverse()
    paginated = ml_data[offset:offset+limit]
    return {"total": len(ml_data), "limit": limit, "offset": offset, "data": paginated}

@app.get("/api/decision/{command_id}")
async def get_decision(command_id: str):
    decision_info = find_decision_by_command_id(command_id)
    if decision_info["decision"] == "not_found":
        raise HTTPException(status_code=404, detail="Command ID not found in any log")
    ml_entries = load_json_file(ML_OUTPUT_FILE)
    ml_info = None
    for entry in ml_entries:
        if entry.get("id") == command_id:
            ml_info = {
                "verdict": entry.get("decision"),
                "reason": entry.get("reason"),
                "anomaly_score": entry.get("score"),
                "attack_probability": entry.get("prob")
            }
            break
    return {
        "command_id": command_id,
        "decision": decision_info["decision"],
        "reason": decision_info["reason"],
        "command_details": decision_info["details"],
        "ml_decision": ml_info
    }

@app.get("/api/recent_activity")
async def get_recent_activity(limit: int = 50):
    accepted = load_json_file(ACCEPTED_FILE)
    alerts = load_json_file(ALERTS_FILE)
    for item in accepted:
        item["type"] = "accepted"
    for item in alerts:
        item["type"] = "rejected"
    combined = accepted + alerts
    combined.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return {"total": len(combined), "limit": limit, "data": combined[:limit]}